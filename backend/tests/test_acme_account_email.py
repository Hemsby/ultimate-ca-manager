"""
Admin edit of a local ACME account contact e-mail (#303 major 4).
"""
import json
import uuid

import pytest

from models import db, AcmeAccount


@pytest.fixture
def acme_acct(app):
    with app.app_context():
        a = AcmeAccount(jwk='{}',
                        jwk_thumbprint=f'email-{uuid.uuid4().hex[:12]}',
                        status='valid',
                        contact=json.dumps(['mailto:old@example.com']))
        db.session.add(a)
        db.session.commit()
        return a.account_id


class TestAccountEmailPatch:
    def _patch(self, auth_client, account_id, body):
        return auth_client.patch(f'/api/v2/acme/accounts/{account_id}', json=body)

    def test_update_email(self, app, auth_client, acme_acct):
        r = self._patch(auth_client, acme_acct, {'email': 'new@example.com'})
        assert r.status_code == 200
        assert r.get_json()['data']['contact'] == ['mailto:new@example.com']
        with app.app_context():
            row = AcmeAccount.query.filter_by(account_id=acme_acct).first()
            assert row.contact_list == ['mailto:new@example.com']

    def test_clear_email(self, auth_client, acme_acct):
        r = self._patch(auth_client, acme_acct, {'email': ''})
        assert r.status_code == 200
        assert r.get_json()['data']['contact'] == []

    def test_tag_only_contact_accepted(self, auth_client, acme_acct):
        # No shape validation at input: invalid addresses are skipped at send time
        r = self._patch(auth_client, acme_acct, {'email': 'infra-tag'})
        assert r.status_code == 200
        assert r.get_json()['data']['contact'] == ['mailto:infra-tag']

    def test_missing_field_and_oversize_rejected(self, auth_client, acme_acct):
        assert self._patch(auth_client, acme_acct, {}).status_code == 400
        assert self._patch(auth_client, acme_acct, {'email': 'x' * 300}).status_code == 400

    def test_non_string_email_rejected(self, auth_client, acme_acct):
        assert self._patch(auth_client, acme_acct, {'email': 123}).status_code == 400
        assert self._patch(auth_client, acme_acct, {'email': ['a@b.c']}).status_code == 400
        # null clears the contact like an empty string
        assert self._patch(auth_client, acme_acct, {'email': None}).status_code == 200

    def test_unknown_account_404(self, auth_client):
        assert self._patch(auth_client, 'nope', {'email': 'a@b.c'}).status_code == 404
