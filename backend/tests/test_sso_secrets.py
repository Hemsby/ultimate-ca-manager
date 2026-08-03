"""
Tests for SSO provider secrets exposure.

Providers are seeded directly in the DB to avoid API uniqueness conflicts.
Tests verify:
- Secrets are encrypted at rest (raw DB column != plaintext)
- to_dict() masks secrets with '***'
- to_dict(include_secrets=True) returns decrypted values
- The API endpoint rejects include_secrets=true for non-admins
- Defense-in-depth: even if a non-admin somehow has read:sso, the admin
  check in the endpoint blocks secrets access
"""
import pytest
import json
import os
import sys

from tests.conftest import get_json, assert_success, assert_error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONTENT_JSON = 'application/json'


def db_session_get(model, obj_id):
    """Fetch a model by ID within the current app context."""
    from models import db
    return db.session.get(model, obj_id)


def _login_as(app, username, password):
    """Log in and return an authenticated test client."""
    c = app.test_client()
    r = c.post('/api/v2/auth/login',
               data=json.dumps({'username': username, 'password': password}),
               content_type='application/json')
    assert r.status_code == 200, f'Login failed for {username}: {r.data}'
    return c


@pytest.fixture()
def oauth2_provider(app):
    """Seed an OAuth2 SSO provider directly in the DB with a known secret.

    Uses a unique name to avoid collisions with other tests.
    Only deletes its own row on teardown.
    """
    from models import db
    from models.sso import SSOProvider

    with app.app_context():
        provider = SSOProvider(
            name='test-oauth2-secrets-idor',
            provider_type='oauth2',
            display_name='Test OAuth2',
            enabled=False,
            default_role='viewer',
            oauth2_client_id='test-client-id',
            oauth2_client_secret='super-secret-value',
            oauth2_auth_url='https://auth.test.com/authorize',
            oauth2_token_url='https://auth.test.com/token',
            oauth2_userinfo_url='https://auth.test.com/userinfo',
        )
        db.session.add(provider)
        db.session.commit()
        pid = provider.id
        # Capture the raw encrypted value before the session closes
        raw_secret = provider._oauth2_client_secret

    yield {'id': pid, 'raw_secret': raw_secret, 'plaintext': 'super-secret-value'}

    with app.app_context():
        SSOProvider.query.filter_by(id=pid).delete()
        db.session.commit()


@pytest.fixture()
def ldap_provider(app):
    """Seed an LDAP SSO provider directly in the DB with a known bind password.

    Uses a unique name to avoid collisions with other tests.
    Only deletes its own row on teardown.
    """
    from models import db
    from models.sso import SSOProvider

    with app.app_context():
        provider = SSOProvider(
            name='test-ldap-secrets-idor',
            provider_type='ldap',
            display_name='Test LDAP',
            enabled=False,
            default_role='viewer',
            ldap_server='ldap.test.com',
            ldap_port=389,
            ldap_bind_dn='cn=admin,dc=test',
            ldap_bind_password='ldap-secret-password',
            ldap_base_dn='ou=users,dc=test',
            ldap_user_filter='(uid={username})',
            ldap_username_attr='uid',
            ldap_email_attr='mail',
            ldap_fullname_attr='cn',
        )
        db.session.add(provider)
        db.session.commit()
        pid = provider.id
        raw_password = provider._ldap_bind_password

    yield {'id': pid, 'raw_password': raw_password, 'plaintext': 'ldap-secret-password'}

    with app.app_context():
        SSOProvider.query.filter_by(id=pid).delete()
        db.session.commit()


class TestSSOSecretsAtRest:
    """#12 — Secrets must be encrypted at rest in the DB."""

    def test_oauth2_secret_encrypted_at_rest(self, app, oauth2_provider):
        """The raw DB column must not contain the plaintext secret."""
        raw = oauth2_provider['raw_secret']
        plaintext = oauth2_provider['plaintext']
        assert raw != plaintext, \
            f'OAuth2 client secret should be encrypted at rest, raw column matches plaintext'
        assert raw is not None, 'Raw secret column should not be None'

    def test_ldap_password_encrypted_at_rest(self, app, ldap_provider):
        """The raw DB column must not contain the plaintext password."""
        raw = ldap_provider['raw_password']
        plaintext = ldap_provider['plaintext']
        assert raw != plaintext, \
            f'LDAP bind password should be encrypted at rest, raw column matches plaintext'
        assert raw is not None, 'Raw password column should not be None'

    def test_oauth2_secret_decrypts_to_plaintext(self, app, oauth2_provider):
        """The model property decrypts the stored value back to plaintext."""
        from models.sso import SSOProvider
        with app.app_context():
            provider = db_session_get(SSOProvider, oauth2_provider['id'])
            assert provider.oauth2_client_secret == oauth2_provider['plaintext'], \
                f'Decrypted secret mismatch: {provider.oauth2_client_secret}'

    def test_ldap_password_decrypts_to_plaintext(self, app, ldap_provider):
        """The model property decrypts the stored password back to plaintext."""
        from models.sso import SSOProvider
        with app.app_context():
            provider = db_session_get(SSOProvider, ldap_provider['id'])
            assert provider.ldap_bind_password == ldap_provider['plaintext'], \
                f'Decrypted password mismatch: {provider.ldap_bind_password}'

    def test_to_dict_masks_oauth2_secret(self, app, oauth2_provider):
        """to_dict() without include_secrets masks the secret with '***'."""
        from models.sso import SSOProvider
        with app.app_context():
            provider = db_session_get(SSOProvider, oauth2_provider['id'])
            data = provider.to_dict(include_secrets=False)
            assert data['oauth2_client_secret'] == '***', \
                f'Secret should be masked, got: {data["oauth2_client_secret"]}'

    def test_to_dict_masks_ldap_password(self, app, ldap_provider):
        """to_dict() without include_secrets masks the password with '***'."""
        from models.sso import SSOProvider
        with app.app_context():
            provider = db_session_get(SSOProvider, ldap_provider['id'])
            data = provider.to_dict(include_secrets=False)
            assert data['ldap_bind_password'] == '***', \
                f'Password should be masked, got: {data["ldap_bind_password"]}'

    def test_to_dict_with_secrets_returns_decrypted_oauth2(self, app, oauth2_provider):
        """to_dict(include_secrets=True) returns the decrypted secret."""
        from models.sso import SSOProvider
        with app.app_context():
            provider = db_session_get(SSOProvider, oauth2_provider['id'])
            data = provider.to_dict(include_secrets=True)
            assert data['oauth2_client_secret'] == oauth2_provider['plaintext'], \
                f'Decrypted secret mismatch: {data["oauth2_client_secret"]}'

    def test_to_dict_with_secrets_returns_decrypted_ldap(self, app, ldap_provider):
        """to_dict(include_secrets=True) returns the decrypted password."""
        from models.sso import SSOProvider
        with app.app_context():
            provider = db_session_get(SSOProvider, ldap_provider['id'])
            data = provider.to_dict(include_secrets=True)
            assert data['ldap_bind_password'] == ldap_provider['plaintext'], \
                f'Decrypted password mismatch: {data["ldap_bind_password"]}'


class TestSSOSecretsAPI:
    """#12 — API endpoint enforces admin-only access to secrets."""

    def test_admin_can_get_oauth2_secrets(self, app, auth_client, oauth2_provider):
        """Admin with include_secrets=true receives the decrypted secret via API."""
        pid = oauth2_provider['id']
        r = auth_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 200, f'Admin should get secrets: {r.data}'
        data = json.loads(r.data).get('data', {})
        assert data.get('oauth2_client_secret') == oauth2_provider['plaintext'], \
            f'Admin should see decrypted secret, got: {data.get("oauth2_client_secret")}'

    def test_admin_can_get_ldap_secrets(self, app, auth_client, ldap_provider):
        """Admin with include_secrets=true receives the decrypted LDAP password via API."""
        pid = ldap_provider['id']
        r = auth_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 200, f'Admin should get LDAP secrets: {r.data}'
        data = json.loads(r.data).get('data', {})
        assert data.get('ldap_bind_password') == ldap_provider['plaintext'], \
            f'Admin should see decrypted LDAP password, got: {data.get("ldap_bind_password")}'

    def test_secrets_masked_without_flag(self, app, auth_client, oauth2_provider):
        """Without include_secrets=true, secrets are masked with ***."""
        pid = oauth2_provider['id']
        r = auth_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 200
        data = json.loads(r.data).get('data', {})
        assert data.get('oauth2_client_secret') == '***', \
            f'Secret should be masked, got: {data.get("oauth2_client_secret")}'

    def test_ldap_password_masked_without_flag(self, app, auth_client, ldap_provider):
        """Without include_secrets=true, LDAP bind password is masked."""
        pid = ldap_provider['id']
        r = auth_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 200
        data = json.loads(r.data).get('data', {})
        assert data.get('ldap_bind_password') == '***', \
            f'LDAP password should be masked, got: {data.get("ldap_bind_password")}'

    def test_include_secrets_false_does_not_leak(self, app, auth_client, oauth2_provider):
        """include_secrets=false explicitly masks secrets."""
        pid = oauth2_provider['id']
        r = auth_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=false')
        assert r.status_code == 200
        data = json.loads(r.data).get('data', {})
        assert data.get('oauth2_client_secret') == '***'

    def test_non_admin_lacks_read_sso(self, app, auth_client, create_user, oauth2_provider):
        """Operator does not have read:sso and gets 403 from @require_auth."""
        create_user(
            username='op_sso_noaccess',
            password='OpPass123!',
            email='op_sso_noaccess@test.local',
            role='operator',
        )
        op_client = _login_as(app, 'op_sso_noaccess', 'OpPass123!')

        pid = oauth2_provider['id']
        r = op_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 403, \
            f'Operator without read:sso should get 403: {r.data}'

    def test_non_admin_lacks_read_sso_no_secrets(self, app, auth_client, create_user, oauth2_provider):
        """Operator without read:sso gets 403 even without include_secrets."""
        create_user(
            username='op_sso_list',
            password='OpPass123!',
            email='op_sso_list@test.local',
            role='operator',
        )
        op_client = _login_as(app, 'op_sso_list', 'OpPass123!')

        pid = oauth2_provider['id']
        r = op_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 403, \
            f'Operator without read:sso should get 403 on basic get: {r.data}'


class TestSSOSecretsDefenseInDepth:
    """#12 — Defense-in-depth: verify the admin role check directly.

    Even if a non-admin user somehow obtains read:sso (e.g., via a future
    role configuration change), the include_secrets check should still
    block them from viewing decrypted secrets.
    """

    def test_admin_check_blocks_non_admin_with_read_sso(
        self, app, auth_client, create_user, monkeypatch, oauth2_provider
    ):
        """Simulate a non-admin user with read:sso and verify include_secrets is blocked."""
        from auth.permissions import ROLE_PERMISSIONS

        create_user(
            username='op_sso_granted',
            password='OpPass123!',
            email='op_sso_granted@test.local',
            role='operator',
        )

        # Temporarily grant read:sso to operator role
        original = ROLE_PERMISSIONS.get('operator', []).copy()
        monkeypatch.setitem(ROLE_PERMISSIONS, 'operator', original + ['read:sso'])

        op_client = _login_as(app, 'op_sso_granted', 'OpPass123!')

        pid = oauth2_provider['id']

        # Operator can now reach the endpoint (read:sso granted)
        r = op_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 200, f'Operator with read:sso should access provider: {r.data}'

        # But include_secrets=true must be blocked by the admin check
        r = op_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 403, \
            f'Non-admin with read:sso should be blocked from secrets: {r.data}'
