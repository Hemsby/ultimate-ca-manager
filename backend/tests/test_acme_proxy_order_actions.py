"""
Proxy orders are client-driven: verify/finalize/renew from the UI must be
refused with a clear 409 instead of reaching the ACME client machinery
(#306: finalize on a proxy order hit the SSRF guard with an empty finalize
URL, "ACME outbound URL blocked: URL has no hostname").

Uses shared conftest fixtures: app, auth_client.
"""
import json

import pytest

from models import db, AcmeClientOrder


def post_json(client, url, data=None):
    return client.post(url, data=json.dumps(data or {}), content_type='application/json')


@pytest.fixture
def proxy_order_id(app):
    def _make(status):
        with app.app_context():
            order = AcmeClientOrder(
                domains='["proxy.example.com"]',
                environment='production',
                challenge_type='dns-01',
                status=status,
                order_url='https://ca.example/acme/order/proxy-1',
                upstream_order_url='https://ca.example/acme/order/proxy-1',
                is_proxy_order=True,
            )
            db.session.add(order)
            db.session.commit()
            return order.id
    yield _make
    with app.app_context():
        AcmeClientOrder.query.filter_by(is_proxy_order=True).delete()
        db.session.commit()


def _assert_client_driven_409(r):
    assert r.status_code == 409, r.get_data(as_text=True)
    body = r.get_json()
    message = json.dumps(body)
    assert 'ACME client' in message and 'proxy' in message
    assert 'no hostname' not in message


def test_finalize_proxy_order_is_refused(auth_client, proxy_order_id):
    oid = proxy_order_id('ready')
    _assert_client_driven_409(
        post_json(auth_client, f'/api/v2/acme/client/orders/{oid}/finalize'))


def test_verify_proxy_order_is_refused(auth_client, proxy_order_id):
    oid = proxy_order_id('pending')
    _assert_client_driven_409(
        post_json(auth_client, f'/api/v2/acme/client/orders/{oid}/verify'))


def test_renew_proxy_order_is_refused(auth_client, proxy_order_id):
    oid = proxy_order_id('valid')
    _assert_client_driven_409(
        post_json(auth_client, f'/api/v2/acme/client/orders/{oid}/renew'))


def test_proxy_order_still_listed_and_deletable(auth_client, proxy_order_id):
    oid = proxy_order_id('pending')
    r = auth_client.get(f'/api/v2/acme/client/orders/{oid}')
    assert r.status_code == 200
    assert r.get_json()['data']['is_proxy_order'] is True
    r = auth_client.delete(f'/api/v2/acme/client/orders/{oid}')
    assert r.status_code == 200
