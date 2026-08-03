"""
Tests for general settings admin permission check.

Verifies that security-sensitive settings (enforce_2fa, session_timeout,
max_login_attempts, lockout_duration, password policy, metrics_token,
key_recovery_dual_control) require admin:settings permission, while
non-security settings (site_name, timezone, date_format) remain
accessible with write:settings only.
"""
import pytest
import json
import os
import sys

from tests.conftest import get_json, assert_success, assert_error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONTENT_JSON = 'application/json'


def patch_json(client, url, data):
    return client.patch(url, data=json.dumps(data), content_type=CONTENT_JSON)


def _login_as(app, username, password):
    """Log in and return an authenticated test client."""
    c = app.test_client()
    r = c.post('/api/v2/auth/login',
               data=json.dumps({'username': username, 'password': password}),
               content_type='application/json')
    assert r.status_code == 200, f'Login failed for {username}: {r.data}'
    return c


def _create_operator(app, auth_client, create_user, username='op_settings_test'):
    """Create an operator (has write:settings but NOT admin:settings) and return logged-in client."""
    create_user(
        username=username,
        password='OpPass123!',
        email=f'{username}@test.local',
        role='operator',
    )
    return _login_as(app, username, 'OpPass123!')


# Settings that require admin:settings
ADMIN_ONLY_KEYS = [
    'enforce_2fa',
    'session_timeout',
    'session_max_lifetime',
    'max_login_attempts',
    'lockout_duration',
    'metrics_token',
    'key_recovery_dual_control',
    'min_password_length',
    'max_password_length',
    'password_require_uppercase',
    'password_require_lowercase',
    'password_require_numbers',
    'password_require_special',
]

# Settings that only need write:settings
NON_ADMIN_KEYS = [
    'site_name',
    'timezone',
    'date_format',
    'show_time',
    'auto_backup_enabled',
    'backup_frequency',
]


class TestGeneralSettingsAdminPermission:
    """#16 — Security-sensitive settings require admin:settings."""

    @pytest.mark.parametrize('key', ADMIN_ONLY_KEYS)
    def test_operator_cannot_modify_admin_setting(self, app, auth_client, create_user, key):
        """Operator with write:settings cannot modify admin-only settings."""
        op_client = _create_operator(app, auth_client, create_user,
                                     f'op_admin_{key[:8]}')

        test_values = {
            'enforce_2fa': False,
            'session_timeout': 99999,
            'session_max_lifetime': 99999,
            'max_login_attempts': 999999,
            'lockout_duration': 0,
            'metrics_token': 'stolen-token',
            'key_recovery_dual_control': False,
            'min_password_length': 1,
            'max_password_length': 1,
            'password_require_uppercase': False,
            'password_require_lowercase': False,
            'password_require_numbers': False,
            'password_require_special': False,
        }

        r = patch_json(op_client, '/api/v2/settings/general', {key: test_values[key]})
        assert r.status_code == 403, \
            f'Operator should be blocked from modifying {key}: {r.data}'

    @pytest.mark.parametrize('key', NON_ADMIN_KEYS)
    def test_operator_can_modify_non_admin_setting(self, app, auth_client, create_user, key):
        """Operator with write:settings can modify non-security settings."""
        op_client = _create_operator(app, auth_client, create_user,
                                     f'op_nonadmin_{key[:8]}')

        test_values = {
            'site_name': 'Operator UCM',
            'timezone': 'America/New_York',
            'date_format': 'long',
            'show_time': False,
            'auto_backup_enabled': True,
            'backup_frequency': 'weekly',
        }

        r = patch_json(op_client, '/api/v2/settings/general', {key: test_values[key]})
        assert r.status_code == 200, \
            f'Operator should be able to modify {key}: {r.data}'

    def test_admin_can_modify_admin_setting(self, auth_client):
        """Admin can modify security-sensitive settings."""
        r = patch_json(auth_client, '/api/v2/settings/general', {'max_login_attempts': 7})
        assert r.status_code == 200, f'Admin should modify admin setting: {r.data}'
        # Restore
        patch_json(auth_client, '/api/v2/settings/general', {'max_login_attempts': 5})

    def test_admin_can_modify_enforce_2fa(self, auth_client):
        """Admin can toggle enforce_2fa."""
        r = patch_json(auth_client, '/api/v2/settings/general', {'enforce_2fa': True})
        assert r.status_code == 200, f'Admin should toggle 2FA: {r.data}'
        # Restore
        patch_json(auth_client, '/api/v2/settings/general', {'enforce_2fa': False})

    def test_operator_blocked_on_multiple_admin_keys(self, app, auth_client, create_user):
        """Operator blocked even when mixing admin and non-admin keys."""
        op_client = _create_operator(app, auth_client, create_user, 'op_mixed')

        r = patch_json(op_client, '/api/v2/settings/general', {
            'site_name': 'Mixed Test',
            'enforce_2fa': False,
            'max_login_attempts': 999,
        })
        assert r.status_code == 403, \
            f'Operator should be blocked when admin keys present: {r.data}'

    def test_operator_can_modify_only_non_admin_keys(self, app, auth_client, create_user):
        """Operator succeeds when only non-admin keys are in the request."""
        op_client = _create_operator(app, auth_client, create_user, 'op_safe')

        r = patch_json(op_client, '/api/v2/settings/general', {
            'site_name': 'Safe Operator',
            'timezone': 'UTC',
            'date_format': 'short',
        })
        assert r.status_code == 200, \
            f'Operator should succeed with only non-admin keys: {r.data}'

    def test_viewer_cannot_modify_any_setting(self, viewer_client):
        """Viewer (read-only) cannot PATCH any setting — requires write:settings."""
        r = patch_json(viewer_client, '/api/v2/settings/general', {'site_name': 'Viewer UCM'})
        assert r.status_code in (403, 401), \
            f'Viewer should not be able to modify settings: {r.data}'
