"""
Tests for ACME proxy ownership checks.

Verifies that authz, challenge, get_order, and cert endpoints reject
cross-account access. Two ACME clients create orders; client A must not
be able to access client B's authz/challenge/order/cert resources.
"""
import base64
import json

import pytest

from models import db, SystemConfig, AcmeClientAccount, AcmeClientOrder
from services.acme.acme_proxy_account import PROXY_ACCOUNT_ID_KEY


_STUB_DIRECTORY_URL = 'https://acme-stub.example/directory'


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


@pytest.fixture(autouse=True)
def _reset_eab_after_test(app):
    yield
    _set_eab_required(app, False)


@pytest.fixture
def proxy_setup(app, monkeypatch):
    """Set up proxy with upstream stub and two client identities."""
    from tests.acme_proxy_upstream_stub import stub_acme_proxy_upstream

    fake_directory = {
        'newNonce': 'https://acme-stub.example/acme/new-nonce',
        'newAccount': 'https://acme-stub.example/acme/new-account',
        'newOrder': 'https://acme-stub.example/acme/new-order',
        'meta': {},
    }
    stub_acme_proxy_upstream(monkeypatch, fake_directory)

    with app.app_context():
        SystemConfig.query.filter_by(key=PROXY_ACCOUNT_ID_KEY).delete()
        AcmeClientAccount.query.filter_by(
            directory_url=_STUB_DIRECTORY_URL
        ).delete()
        AcmeClientOrder.query.filter_by(is_proxy_order=True).delete()
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

    yield {
        'key_a': key_a, 'jwk_a': jwk_a,
        'key_b': key_b, 'jwk_b': jwk_b,
    }

    with app.app_context():
        SystemConfig.query.filter_by(key=PROXY_ACCOUNT_ID_KEY).delete()
        AcmeClientAccount.query.filter_by(
            directory_url=_STUB_DIRECTORY_URL
        ).delete()
        AcmeClientOrder.query.filter_by(is_proxy_order=True).delete()
        db.session.commit()


def _create_account_and_order(app, client, key, jwk, domain):
    """Create a proxy account and order, return (kid, order_url, authz_url, chall_url, cert_url)."""
    nonce = _get_nonce(client)
    url_acct = 'http://localhost/acme/proxy/new-account'
    jws_acct = _build_jws(url_acct, {'termsOfServiceAgreed': True}, jwk, key, nonce=nonce)
    r_acct = client.post(
        '/acme/proxy/new-account',
        data=json.dumps(jws_acct),
        content_type='application/jose+json',
    )
    assert r_acct.status_code == 201, f'Account creation failed: {r_acct.data}'
    kid = r_acct.headers['Location']

    nonce2 = _get_nonce(client)
    url_order = 'http://localhost/acme/proxy/new-order'
    payload = {'identifiers': [{'type': 'dns', 'value': domain}]}
    jws_order = _build_jws(url_order, payload, jwk, key, nonce=nonce2, use_kid=kid)
    r_order = client.post(
        '/acme/proxy/new-order',
        data=json.dumps(jws_order),
        content_type='application/jose+json',
    )
    assert r_order.status_code == 201, f'Order creation failed: {r_order.data}'
    order_data = r_order.get_json()
    order_url = order_data.get('Location', '')
    authz_url = order_data.get('authorizations', [None])[0] if order_data.get('authorizations') else None
    finalize_url = order_data.get('finalize')

    return kid, order_url, authz_url, finalize_url


class TestAcmeProxyOwnershipAuthz:
    """#4 — authz endpoint must verify ownership."""

    def test_authz_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot fetch client A's authz."""
        kid_a, order_url_a, authz_url_a, _ = _create_account_and_order(
            app, client, proxy_setup['key_a'], proxy_setup['jwk_a'], 'a.example.com'
        )
        _create_account_and_order(
            app, client, proxy_setup['key_b'], proxy_setup['jwk_b'], 'b.example.com'
        )

        if not authz_url_a:
            pytest.skip('No authz URL returned from new-order')

        authz_id = authz_url_a.split('/')[-1]
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/authz/{authz_id}'
        jws = _build_jws(url, '', proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid='http://localhost/acme/proxy/acct/b')

        r = client.post(
            f'/acme/proxy/authz/{authz_id}',
            data=json.dumps(jws),
            content_type='application/jose+json',
        )
        assert r.status_code == 403, f'Cross-account authz should be denied: {r.data}'


class TestAcmeProxyOwnershipChallenge:
    """#4 — challenge endpoint must verify ownership."""

    def test_challenge_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot respond to client A's challenge."""
        kid_a, order_url_a, authz_url_a, _ = _create_account_and_order(
            app, client, proxy_setup['key_a'], proxy_setup['jwk_a'], 'a.example.com'
        )
        _create_account_and_order(
            app, client, proxy_setup['key_b'], proxy_setup['jwk_b'], 'b.example.com'
        )

        if not authz_url_a:
            pytest.skip('No authz URL returned from new-order')

        chall_id = _b64url(authz_url_a + '/0')
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/challenge/{chall_id}'
        jws = _build_jws(url, {}, proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid='http://localhost/acme/proxy/acct/b')

        r = client.post(
            f'/acme/proxy/challenge/{chall_id}',
            data=json.dumps(jws),
            content_type='application/jose+json',
        )
        assert r.status_code == 403, f'Cross-account challenge should be denied: {r.data}'


class TestAcmeProxyOwnershipGetOrder:
    """#4 — get_order endpoint must verify ownership."""

    def test_get_order_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot view client A's order."""
        kid_a, order_url_a, _, _ = _create_account_and_order(
            app, client, proxy_setup['key_a'], proxy_setup['jwk_a'], 'a.example.com'
        )
        _create_account_and_order(
            app, client, proxy_setup['key_b'], proxy_setup['jwk_b'], 'b.example.com'
        )

        if not order_url_a:
            pytest.skip('No order URL returned')

        order_id = _b64url(order_url_a)
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/order/{order_id}'
        jws = _build_jws(url, '', proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid='http://localhost/acme/proxy/acct/b')

        r = client.post(
            f'/acme/proxy/order/{order_id}',
            data=json.dumps(jws),
            content_type='application/jose+json',
        )
        assert r.status_code == 403, f'Cross-account order view should be denied: {r.data}'


class TestAcmeProxyOwnershipCert:
    """#4 — cert endpoint must verify ownership."""

    def test_cert_cross_account_denied(self, app, client, proxy_setup):
        """Client B cannot download client A's certificate."""
        kid_a, order_url_a, _, _ = _create_account_and_order(
            app, client, proxy_setup['key_a'], proxy_setup['jwk_a'], 'a.example.com'
        )
        _create_account_and_order(
            app, client, proxy_setup['key_b'], proxy_setup['jwk_b'], 'b.example.com'
        )

        cert_url = 'https://acme-stub.example/acme/cert/1'
        cert_id = _b64url(cert_url)
        nonce = _get_nonce(client)
        url = f'http://localhost/acme/proxy/cert/{cert_id}'
        jws = _build_jws(url, '', proxy_setup['jwk_b'], proxy_setup['key_b'],
                         nonce=nonce, use_kid='http://localhost/acme/proxy/acct/b')

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
