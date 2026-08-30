"""
Expired local ACME order purge and admin order management (#303).
"""
import json
from datetime import timedelta

import pytest

from models import db
from models.acme_models import (
    AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeOrder,
)
from services.acme.order_purge import purge_expired_orders
from utils.datetime_utils import utc_now


def _mk_order(account_id, status='pending', expired=True, with_children=True):
    order = AcmeOrder(
        account_id=account_id,
        status=status,
        identifiers=json.dumps([{'type': 'dns', 'value': 'purge.example.com'}]),
    )
    if expired:
        order.expires = utc_now() - timedelta(days=1)
    db.session.add(order)
    db.session.flush()
    if with_children:
        authz = AcmeAuthorization(
            order_id=order.order_id,
            account_id=account_id,
            identifier=json.dumps({'type': 'dns', 'value': 'purge.example.com'}),
            status='pending',
        )
        db.session.add(authz)
        db.session.flush()
        db.session.add(AcmeChallenge(
            authorization_id=authz.authorization_id,
            type='dns-01', status='pending',
        ))
    db.session.commit()
    return order.id


@pytest.fixture
def acct(app):
    # Session-scoped shared DB, no per-test rollback: the thumbprint must be
    # unique per instantiation.
    import uuid
    with app.app_context():
        a = AcmeAccount(jwk='{}',
                        jwk_thumbprint=f'purge-{uuid.uuid4().hex[:12]}',
                        status='valid')
        db.session.add(a)
        db.session.commit()
        return a.account_id


class TestPurge:
    def test_expired_pending_order_is_removed_with_children(self, app, acct):
        with app.app_context():
            oid = _mk_order(acct)
            stats = purge_expired_orders()
            assert stats['orders'] >= 1
            assert db.session.get(AcmeOrder, oid) is None
            assert AcmeAuthorization.query.filter_by(account_id=acct).count() == 0

    def test_valid_and_unexpired_orders_are_kept(self, app, acct):
        with app.app_context():
            kept_valid = _mk_order(acct, status='valid', expired=True)
            kept_live = _mk_order(acct, status='pending', expired=False)
            purge_expired_orders()
            assert db.session.get(AcmeOrder, kept_valid) is not None
            assert db.session.get(AcmeOrder, kept_live) is not None
            # cleanup
            for oid in (kept_valid, kept_live):
                o = db.session.get(AcmeOrder, oid)
                for authz in list(o.authorizations):
                    AcmeChallenge.query.filter_by(
                        authorization_id=authz.authorization_id).delete()
                    db.session.delete(authz)
                db.session.delete(o)
            db.session.commit()

    def test_orphan_expired_authz_is_removed(self, app, acct):
        with app.app_context():
            authz = AcmeAuthorization(
                order_id=None, account_id=acct,
                identifier=json.dumps({'type': 'dns', 'value': 'orphan.example.com'}),
                status='pending',
            )
            authz.expires = utc_now() - timedelta(days=1)
            db.session.add(authz)
            db.session.commit()
            authz_id = authz.authorization_id
            purge_expired_orders()
            assert AcmeAuthorization.query.filter_by(
                authorization_id=authz_id).count() == 0


class TestOrdersAdminApi:
    def test_list_is_paginated(self, app, auth_client, acct):
        with app.app_context():
            ids = [_mk_order(acct, expired=False, with_children=False)
                   for _ in range(3)]
        r = auth_client.get('/api/v2/acme/orders?per_page=2&page=1')
        assert r.status_code == 200
        body = r.get_json()['data']
        assert len(body['items']) == 2
        assert body['meta']['total'] >= 3
        with app.app_context():
            for oid in ids:
                db.session.delete(db.session.get(AcmeOrder, oid))
            db.session.commit()

    def test_delete_removes_order_and_children(self, app, auth_client, acct):
        with app.app_context():
            oid = _mk_order(acct, expired=False)
        r = auth_client.delete(f'/api/v2/acme/orders/{oid}')
        assert r.status_code == 200
        with app.app_context():
            assert db.session.get(AcmeOrder, oid) is None
        assert auth_client.delete(f'/api/v2/acme/orders/{oid}').status_code == 404

    def test_purge_now_endpoint(self, app, auth_client, acct):
        with app.app_context():
            _mk_order(acct)
        r = auth_client.post('/api/v2/acme/orders/purge')
        assert r.status_code == 200
        assert r.get_json()['data']['orders'] >= 1
