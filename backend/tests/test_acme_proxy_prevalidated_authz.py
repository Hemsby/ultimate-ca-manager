"""#325: an upstream authorization the CA has already validated (pre-validated
or onboarded domain) carries no pending dns-01 challenge. The proxy must pass
it through instead of failing with the dns-01-only error, while a pending
authorization without dns-01 is still refused."""
import json

import pytest

from models import db, AcmeClientOrder


class _Resp:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


def _seed_order(authz_url, domain):
    AcmeClientOrder.query.filter_by(is_proxy_order=True).delete()
    order = AcmeClientOrder(
        domains=json.dumps([domain]),
        environment='staging',
        challenge_type='dns-01',
        status='pending',
        order_url='https://ca.example/acme/order/pv',
        upstream_order_url='https://ca.example/acme/order/pv',
        upstream_authz_urls=json.dumps([authz_url]),
        is_proxy_order=True,
        account_id='acct-pv',
        client_jwk_thumbprint='thumb-pv',
    )
    db.session.add(order)
    db.session.commit()
    return order


def _service(monkeypatch, upstream_authz):
    from services.acme.acme_proxy_service import AcmeProxyService
    svc = AcmeProxyService('https://ucm.example/acme/proxy')
    monkeypatch.setattr(svc, 'upstream_directory_url', 'https://ca.example/acme/directory')
    monkeypatch.setattr(svc, '_post_with_account', lambda *_a, **_k: _Resp(upstream_authz))
    return svc


class TestPrevalidatedAuthorization:
    def test_valid_upstream_authz_without_dns01_is_passed_through(self, app, monkeypatch):
        authz_url = 'https://ca.example/acme/authz/pv-1'
        upstream = {
            'identifier': {'type': 'dns', 'value': 'prevalidated.example.com'},
            'status': 'valid',
            'expires': '2027-01-01T00:00:00Z',
            'challenges': [
                {'type': 'http-01', 'status': 'valid', 'url': 'https://ca.example/acme/chall/pv-1-http',
                 'token': 'tok', 'validated': '2026-01-01T00:00:00Z'},
            ],
        }
        with app.app_context():
            _seed_order(authz_url, 'prevalidated.example.com')
            svc = _service(monkeypatch, upstream)
            thread_started = []
            monkeypatch.setattr('threading.Thread.start', lambda self_: thread_started.append(self_))

            authz, identifier = svc.get_authz(
                svc._proxy_id(authz_url),
                requester_account_id='acct-pv', requester_thumbprint='thumb-pv',
            )

        assert identifier['value'] == 'prevalidated.example.com'
        assert authz['status'] == 'valid'
        assert len(authz['challenges']) == 1
        assert authz['challenges'][0]['type'] == 'http-01'
        assert authz['challenges'][0]['url'].startswith('https://ucm.example/acme/proxy/challenge/')
        assert thread_started == [], 'no DNS automation for an already valid authorization'

    def test_valid_upstream_authz_with_empty_challenges_is_passed_through(self, app, monkeypatch):
        authz_url = 'https://ca.example/acme/authz/pv-2'
        upstream = {
            'identifier': {'type': 'dns', 'value': 'onboarded.example.com'},
            'status': 'valid',
            'challenges': [],
        }
        with app.app_context():
            _seed_order(authz_url, 'onboarded.example.com')
            svc = _service(monkeypatch, upstream)
            authz, _ = svc.get_authz(
                svc._proxy_id(authz_url),
                requester_account_id='acct-pv', requester_thumbprint='thumb-pv',
            )
        assert authz['status'] == 'valid'
        assert authz['challenges'] == []

    def test_pending_upstream_authz_without_dns01_is_still_refused(self, app, monkeypatch):
        from services.acme.acme_proxy_service import ProxyDns01OnlyError
        authz_url = 'https://ca.example/acme/authz/pv-3'
        upstream = {
            'identifier': {'type': 'dns', 'value': 'pending.example.com'},
            'status': 'pending',
            'challenges': [
                {'type': 'http-01', 'status': 'pending', 'url': 'https://ca.example/acme/chall/pv-3-http', 'token': 't'},
            ],
        }
        with app.app_context():
            _seed_order(authz_url, 'pending.example.com')
            svc = _service(monkeypatch, upstream)
            with pytest.raises(ProxyDns01OnlyError):
                svc.get_authz(
                    svc._proxy_id(authz_url),
                    requester_account_id='acct-pv', requester_thumbprint='thumb-pv',
                )
