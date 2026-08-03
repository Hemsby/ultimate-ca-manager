"""
Tests for ACME proxy ownership checks.

Verifies that authz, challenge, get_order, and cert endpoints reject
cross-account access. Orders are seeded directly in the DB (bypassing
the new-order API which requires DNS provider configuration). The
ownership check runs before any upstream call, so cross-account
requests are rejected with 403 without needing upstream stubs for
authz/challenge/order/cert responses.
"""
import base64
import json

import pytest

from models import db, SystemConfig, AcmeClientAccount, AcmeClientOrder
from services.acme.acme_proxy_account import PROXY_ACCOUNT_ID_KEY


_STUB_DIRECTORY_URL = 'https://acme-ownership-stub.example/directory'
_UPSTREAM_HOST = 'acme-ownership-stub.example'


def _set_eab_required(app, enabled):
    with app.app_context():
        row = SystemConfig.query.filter_by(key='acme_eab_required').first()
        if not row:
            row = SystemConfig(key='acme_eab_required', description='test')
            db.session.add(row)
        row.value = 'true' if enabled else 'false'
        db.session.commit()


def _get_nonce(client):
    r = client.get('/acme/proxy/new-nonce')
    return r.headers.get('Replay-Nonce', 'fallback-nonce')


def _generate_rsa_key_and_jwk():
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = private_key.public_key().public_numbers()

    def int_to_b64(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

    jwk = {'kty': 'RSA', 'n': int_to_b64(pub.n), 'e': int_to_b64(pub.e)}
    return private_key, jwk


def _build_jws(url, payload, jwk, private_key, nonce='test-nonce', use_kid=None):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    protected = {'alg': 'RS256', 'nonce': nonce, 'url': url}
    if use_kid:
        protected['kid'] = use_kid
    else:
        protected['jwk'] = jwk

    protected_b64 = base64.urlsafe_b64encode(
        json.dumps(protected).encode()
    ).rstrip(b'=').decode()

    if payload is not None:
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()
    else:
        payload_b64 = ''

    signing_input = f'{protected_b64}.{payload_b64}'.encode()
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

    return {'protected': protected_b64, 'payload': payload_b64, 'signature': sig_b64}


def _b64url(s):
    return base64.urlsafe_b64encode(s.encode()).rstrip(b'=').decode()


def _compute_thumbprint(jwk):
    import hashlib
    jwk_canonical = json.dumps(jwk, separators=(',', ':'), sort_keys=True)
    return base64.urlsafe_b64encode(
        hashlib.sha256(jwk_canonical.encode()).digest()
    ).rstrip(b'=').decode()


@pytest.fixture(autouse=True)
def _reset_eab_after_test(app):
    yield
    _set_eab_required(app, False)


@pytest.fixture
def proxy_setup(app, monkeypatch):
    """Set up proxy with upstream stub and two client identities.

    Creates two ACME proxy accounts via the API (new-account does not
    require DNS provider), then seeds two proxy orders directly in the
    DB with known account_ids and thumbprints.
    """
    from tests.acme_proxy_upstream_stub import stub_acme_proxy_upstream

    fake_directory = {
        'newNonce': f'https://{_UPSTREAM_HOST}/acme/new-nonce',
        'newAccount': f'https://{_UPSTREAM_HOST}/acme/new-account',
        'newOrder': f'https://{_UPSTREAM_HOST}/acme/new-order',
        'meta': {},
    }
    stub_acme_proxy_upstream(monkeypatch, fake_directory)

    with app.app_context():
        # Save original PROXY_ACCOUNT_ID_KEY value to restore later
        orig_proxy_id = SystemConfig.query.filter_by(key=PROXY_ACCOUNT_ID_KEY).first()
        orig_proxy_id_val = orig_proxy_id.value if orig_proxy_id else None
        # Delete only our own config row — don't touch other tests' data
        SystemConfig.query.filter_by(key=PROXY_ACCOUNT_ID_KEY).delete()
        # Delete only our own account (by unique directory_url) — don't touch other tests'
        AcmeClientAccount.query.filter_by(
            directory_url=_STUB_DIRECTORY_URL
        ).delete()
        db.session.commit()

        acct = AcmeClientAccount(
            directory_url=_STUB_DIRECTORY_URL,
            label='Proxy Ownership Test',
            email='ownership@example.com',
        )
        db.session.add(acct)
        db.session.commit()
        db.session.add(SystemConfig(
            key=PROXY_ACCOUNT_ID_KEY,
            value=str(acct.id),
            description='test proxy ownership',
        ))
        db.session.commit()

    # Two client key pairs
    key_a, jwk_a = _generate_rsa_key_and_jwk()
    key_b, jwk_b = _generate_rsa_key_and_jwk()
    thumb_a = _compute_thumbprint(jwk_a)
    thumb_b = _compute_thumbprint(jwk_b)

    # Create two accounts via the API (new-account works without DNS provider)
    _set_eab_required(app, False)

    kid_a = _create_proxy_account(app, client_fixture=None, key=key_a, jwk=jwk_a)
    kid_b = _create_proxy_account(app, client_fixture=None, key=key_b, jwk=jwk_b)

    # Unique upstream URLs for seeded orders (unique paths to avoid collisions
    # with other test files that use the same stub host)
    authz_url_a = f'https://{_UPSTREAM_HOST}/acme/authz/ownership-a'
    authz_url_b = f'https://{_UPSTREAM_HOST}/acme/authz/ownership-b'
    order_url_a = f'https://{_UPSTREAM_HOST}/acme/order/ownership-a'
    order_url_b = f'https://{_UPSTREAM_HOST}/acme/order/ownership-b'
    cert_url_a = f'https://{_UPSTREAM_HOST}/acme/cert/ownership-a'
    chall_url_a = f'https://{_UPSTREAM_HOST}/acme/challenge/ownership-a/0'

    # Seed two orders directly in the DB
    with app.app_context():
        order_a = AcmeClientOrder(
            domains='["a.example.com"]',
            environment='staging',
            challenge_type='dns-01',
            status='pending',
            order_url=order_url_a,
            upstream_order_url=order_url_a,
            upstream_authz_urls=json.dumps([authz_url_a]),
            is_proxy_order=True,
            account_id=kid_a.split('/')[-1],
            client_jwk_thumbprint=thumb_a,
            certificate_url=cert_url_a,
        )
        order_b = AcmeClientOrder(
            domains='["b.example.com"]',
            environment='staging',
            challenge_type='dns-01',
            status='pending',
            order_url=order_url_b,
            upstream_order_url=order_url_b,
            upstream_authz_urls=json.dumps([authz_url_b]),
            is_proxy_order=True,
            account_id=kid_b.split('/')[-1],
            client_jwk_thumbprint=thumb_b,
        )
        db.session.add_all([order_a, order_b])
        db.session.commit()
        order_a_id = order_a.id
        order_b_id = order_b.id

    yield {
        'key_a': key_a, 'jwk_a': jwk_a, 'kid_a': kid_a, 'thumb_a': thumb_a,
        'key_b': key_b, 'jwk_b': jwk_b, 'kid_b': kid_b, 'thumb_b': thumb_b,
        'authz_url_a': authz_url_a, 'authz_url_b': authz_url_b,
        'order_url_a': order_url_a, 'order_url_b': order_url_b,
        'cert_url_a': cert_url_a, 'chall_url_a': chall_url_a,
    }

    with app.app_context():
        # Restore original PROXY_ACCOUNT_ID_KEY value (don't just delete it)
        SystemConfig.query.filter_by(key=PROXY_ACCOUNT_ID_KEY).delete()
        if orig_proxy_id_val is not None:
            db.session.add(SystemConfig(
                key=PROXY_ACCOUNT_ID_KEY,
                value=orig_proxy_id_val,
                description='restored',
            ))
        # Delete only our own rows — by specific IDs, not by host-wide filters
        AcmeClientOrder.query.filter_by(id=order_a_id).delete()
        AcmeClientOrder.query.filter_by(id=order_b_id).delete()
        AcmeClientAccount.query.filter_by(
            directory_url=_STUB_DIRECTORY_URL
        ).delete()
        db.session.commit()


def _create_proxy_account(app, client_fixture, key, jwk):
    """Create a proxy account via the API and return the kid URL."""
    client = app.test_client()
    nonce = _get_nonce(client)
    url_acct = 'http://localhost/acme/proxy/new-account'
    jws_acct = _build_jws(url_acct, {'termsOfServiceAgreed': True}, jwk, key, nonce=nonce)
    r_acct = client.post(
        '/acme/proxy/new-account',
        data=json.dumps(jws_acct),
        content_type='application/jose+json',
    )
    assert r_acct.status_code == 201, f'Account creation failed: {r_acct.data}'
    return r_acct.headers['Location']


class TestAcmeProxyOwnershipAuthz:
    """#4 — authz endpoint must verify ownership."""

    def test_authz_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot fetch client A's authz."""
        authz_id = _b64url(proxy_setup['authz_url_a'])
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/authz/{authz_id}'
        jws = _build_jws(url, '', proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid=proxy_setup['kid_b'])

        r = client.post(
            f'/acme/proxy/authz/{authz_id}',
            data=json.dumps(jws),
            content_type='application/jose+json',
        )
        assert r.status_code == 403, f'Cross-account authz should be denied: {r.data}'


class TestAcmeProxyOwnershipChallenge:
    """#5 — challenge endpoint must verify ownership."""

    def test_challenge_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot respond to client A's challenge."""
        chall_id = _b64url(proxy_setup['chall_url_a'])
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/challenge/{chall_id}'
        jws = _build_jws(url, {}, proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid=proxy_setup['kid_b'])

        r = client.post(
            f'/acme/proxy/challenge/{chall_id}',
            data=json.dumps(jws),
            content_type='application/jose+json',
        )
        assert r.status_code == 403, f'Cross-account challenge should be denied: {r.data}'


class TestAcmeProxyOwnershipGetOrder:
    """#6 — get_order endpoint must verify ownership."""

    def test_get_order_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot view client A's order."""
        order_id = _b64url(proxy_setup['order_url_a'])
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/order/{order_id}'
        jws = _build_jws(url, '', proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid=proxy_setup['kid_b'])

        r = client.post(
            f'/acme/proxy/order/{order_id}',
            data=json.dumps(jws),
            content_type='application/jose+json',
        )
        assert r.status_code == 403, f'Cross-account order view should be denied: {r.data}'


class TestAcmeProxyOwnershipCert:
    """#7 — cert endpoint must verify ownership."""

    def test_cert_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot download client A's certificate."""
        cert_id = _b64url(proxy_setup['cert_url_a'])
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/cert/{cert_id}'
        jws = _build_jws(url, '', proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid=proxy_setup['kid_b'])

        r = client.post(
            f'/acme/proxy/cert/{cert_id}',
            data=json.dumps(jws),
            content_type='application/jose+json',
        )
        assert r.status_code == 403, f'Cross-account cert download should be denied: {r.data}'


class TestAcmeProxyOwnershipServiceLevel:
    """Service-level ownership verification tests (#5, #6, #7)."""

    def test_verify_order_ownership_matching_account(self, app):
        """Ownership check passes when account_id matches."""
        from services.acme.acme_proxy_service import AcmeProxyService

        with app.app_context():
            order = AcmeClientOrder(
                domains='["test.example.com"]',
                environment='staging',
                challenge_type='dns-01',
                status='pending',
                order_url='https://ca.example/acme/order/1',
                upstream_order_url='https://ca.example/acme/order/1',
                is_proxy_order=True,
                account_id='acct-1',
                client_jwk_thumbprint='thumb-1',
            )
            db.session.add(order)
            db.session.commit()

            AcmeProxyService._verify_order_ownership(
                order, requester_account_id='acct-1', requester_thumbprint='thumb-1'
            )
            db.session.delete(order)
            db.session.commit()

    def test_verify_order_ownership_mismatched_account(self, app):
        """Ownership check raises PermissionError when account_id differs."""
        from services.acme.acme_proxy_service import AcmeProxyService

        with app.app_context():
            order = AcmeClientOrder(
                domains='["test.example.com"]',
                environment='staging',
                challenge_type='dns-01',
                status='pending',
                order_url='https://ca.example/acme/order/2',
                upstream_order_url='https://ca.example/acme/order/2',
                is_proxy_order=True,
                account_id='acct-1',
                client_jwk_thumbprint='thumb-1',
            )
            db.session.add(order)
            db.session.commit()

            with pytest.raises(PermissionError):
                AcmeProxyService._verify_order_ownership(
                    order, requester_account_id='acct-2', requester_thumbprint='thumb-2'
                )
            db.session.delete(order)
            db.session.commit()

    def test_verify_order_ownership_no_identity_for_owned_order(self, app):
        """Ownership check raises PermissionError when no identity provided for owned order."""
        from services.acme.acme_proxy_service import AcmeProxyService

        with app.app_context():
            order = AcmeClientOrder(
                domains='["test.example.com"]',
                environment='staging',
                challenge_type='dns-01',
                status='pending',
                order_url='https://ca.example/acme/order/3',
                upstream_order_url='https://ca.example/acme/order/3',
                is_proxy_order=True,
                account_id='acct-1',
                client_jwk_thumbprint='thumb-1',
            )
            db.session.add(order)
            db.session.commit()

            with pytest.raises(PermissionError):
                AcmeProxyService._verify_order_ownership(
                    order, requester_account_id=None, requester_thumbprint=None
                )
            db.session.delete(order)
            db.session.commit()

    def test_verify_order_ownership_legacy_order_allowed(self, app):
        """Legacy orders without ownership info are allowed (backward compat)."""
        from services.acme.acme_proxy_service import AcmeProxyService

        with app.app_context():
            order = AcmeClientOrder(
                domains='["legacy.example.com"]',
                environment='staging',
                challenge_type='dns-01',
                status='pending',
                order_url='https://ca.example/acme/order/legacy',
                upstream_order_url='https://ca.example/acme/order/legacy',
                is_proxy_order=True,
            )
            db.session.add(order)
            db.session.commit()

            AcmeProxyService._verify_order_ownership(
                order, requester_account_id='any-acct', requester_thumbprint='any-thumb'
            )
            db.session.delete(order)
            db.session.commit()
