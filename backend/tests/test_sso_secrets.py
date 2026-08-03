"""
Tests for SSO provider secrets exposure.

Verifies that the get_provider endpoint with ?include_secrets=true
is rejected for non-admin users. Only admins should be able to
retrieve decrypted OAuth2 client secrets or LDAP bind passwords.

NOTE: In the current permission model, only admin has read:sso (via
the '*' wildcard). The include_secrets admin check is defense-in-depth:
it protects against future role changes that might grant read:sso to
other roles. These tests verify both the current behavior (non-admins
get 401 from @require_auth) and the defense-in-depth check (a non-admin
who somehow has read:sso is still blocked from secrets).
"""
import pytest
import json
import os
import sys

from tests.conftest import get_json, assert_success, assert_error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONTENT_JSON = 'application/json'


def _login_as(app, username, password):
    """Log in and return an authenticated test client."""
    c = app.test_client()
    r = c.post('/api/v2/auth/login',
               data=json.dumps({'username': username, 'password': password}),
               content_type='application/json')
    assert r.status_code == 200, f'Login failed for {username}: {r.data}'
    return c


def _create_oauth2_provider(auth_client, name='test-oauth2-secrets'):
    """Create an OAuth2 SSO provider with a client secret."""
    r = auth_client.post('/api/v2/sso/providers',
        data=json.dumps({
            'name': name,
            'provider_type': 'oauth2',
            'display_name': 'Test OAuth2',
            'enabled': False,
            'default_role': 'viewer',
            'oauth2_client_id': 'test-client-id',
            'oauth2_client_secret': 'super-secret-value',
            'oauth2_auth_url': 'https://auth.test.com/authorize',
            'oauth2_token_url': 'https://auth.test.com/token',
            'oauth2_userinfo_url': 'https://auth.test.com/userinfo',
        }),
        content_type='application/json')
    assert r.status_code in (200, 201), f'Create OAuth2 provider failed: {r.data}'
    data = json.loads(r.data)
    return data.get('data', data)


def _create_ldap_provider(auth_client, name='test-ldap-secrets'):
    """Create an LDAP SSO provider with a bind password."""
    r = auth_client.post('/api/v2/sso/providers',
        data=json.dumps({
            'name': name,
            'provider_type': 'ldap',
            'display_name': 'Test LDAP',
            'enabled': False,
            'default_role': 'viewer',
            'ldap_server': 'ldap.test.com',
            'ldap_port': 389,
            'ldap_bind_dn': 'cn=admin,dc=test',
            'ldap_bind_password': 'ldap-secret-password',
            'ldap_base_dn': 'ou=users,dc=test',
            'ldap_user_filter': '(uid={username})',
            'ldap_username_attr': 'uid',
            'ldap_email_attr': 'mail',
            'ldap_fullname_attr': 'cn',
        }),
        content_type='application/json')
    assert r.status_code in (200, 201), f'Create LDAP provider failed: {r.data}'
    data = json.loads(r.data)
    return data.get('data', data)


class TestSSOSecretsExposure:
    """#12 — Non-admin users must not access ?include_secrets=true."""

    def test_admin_can_get_oauth2_secrets(self, app, auth_client):
        """Admin with include_secrets=true receives the decrypted secret."""
        provider = _create_oauth2_provider(auth_client, 'admin-oauth2-view')
        pid = provider['id']

        r = auth_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 200, f'Admin should get secrets: {r.data}'
        data = json.loads(r.data).get('data', {})
        assert data.get('oauth2_client_secret') == 'super-secret-value', \
            f'Admin should see decrypted secret, got: {data.get("oauth2_client_secret")}'

    def test_admin_can_get_ldap_secrets(self, app, auth_client):
        """Admin with include_secrets=true receives the decrypted LDAP bind password."""
        provider = _create_ldap_provider(auth_client, 'admin-ldap-view')
        pid = provider['id']

        r = auth_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 200, f'Admin should get LDAP secrets: {r.data}'
        data = json.loads(r.data).get('data', {})
        assert data.get('ldap_bind_password') == 'ldap-secret-password', \
            f'Admin should see decrypted LDAP password, got: {data.get("ldap_bind_password")}'

    def test_non_admin_lacks_read_sso(self, app, auth_client, create_user):
        """Operator does not have read:sso and gets 401 from @require_auth."""
        create_user(
            username='op_sso_noaccess',
            password='OpPass123!',
            email='op_sso_noaccess@test.local',
            role='operator',
        )
        op_client = _login_as(app, 'op_sso_noaccess', 'OpPass123!')

        provider = _create_oauth2_provider(auth_client, 'op-noaccess')
        pid = provider['id']

        r = op_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 401, \
            f'Operator without read:sso should get 401: {r.data}'

    def test_non_admin_lacks_read_sso_no_secrets(self, app, auth_client, create_user):
        """Operator without read:sso gets 401 even without include_secrets."""
        create_user(
            username='op_sso_list',
            password='OpPass123!',
            email='op_sso_list@test.local',
            role='operator',
        )
        op_client = _login_as(app, 'op_sso_list', 'OpPass123!')

        provider = _create_oauth2_provider(auth_client, 'op-list')
        pid = provider['id']

        r = op_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 401, \
            f'Operator without read:sso should get 401 on basic get: {r.data}'

    def test_secrets_masked_without_flag(self, app, auth_client):
        """Without include_secrets=true, secrets are masked with ***."""
        provider = _create_oauth2_provider(auth_client, 'masked-oauth2')
        pid = provider['id']

        r = auth_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 200
        data = json.loads(r.data).get('data', {})
        assert data.get('oauth2_client_secret') == '***', \
            f'Secret should be masked, got: {data.get("oauth2_client_secret")}'

    def test_ldap_password_masked_without_flag(self, app, auth_client):
        """Without include_secrets=true, LDAP bind password is masked."""
        provider = _create_ldap_provider(auth_client, 'masked-ldap')
        pid = provider['id']

        r = auth_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 200
        data = json.loads(r.data).get('data', {})
        assert data.get('ldap_bind_password') == '***', \
            f'LDAP password should be masked, got: {data.get("ldap_bind_password")}'

    def test_include_secrets_false_does_not_leak(self, app, auth_client):
        """include_secrets=false explicitly masks secrets."""
        provider = _create_oauth2_provider(auth_client, 'explicit-false')
        pid = provider['id']

        r = auth_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=false')
        assert r.status_code == 200
        data = json.loads(r.data).get('data', {})
        assert data.get('oauth2_client_secret') == '***'


class TestSSOSecretsDefenseInDepth:
    """#12 — Defense-in-depth: verify the admin role check directly.

    Even if a non-admin user somehow obtains read:sso (e.g., via a future
    role configuration change), the include_secrets check should still
    block them from viewing decrypted secrets.
    """

    def test_admin_check_blocks_non_admin_with_read_sso(self, app, auth_client, create_user, monkeypatch):
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

        provider = _create_oauth2_provider(auth_client, 'op-granted')
        pid = provider['id']

        # Operator can now reach the endpoint (read:sso granted)
        r = op_client.get(f'/api/v2/sso/providers/{pid}')
        assert r.status_code == 200, f'Operator with read:sso should access provider: {r.data}'

        # But include_secrets=true must be blocked by the admin check
        r = op_client.get(f'/api/v2/sso/providers/{pid}?include_secrets=true')
        assert r.status_code == 403, \
            f'Non-admin with read:sso should be blocked from secrets: {r.data}'
