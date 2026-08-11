"""
Active Directory Connector settings routes
/api/v2/ad-connector/* -- single stored LDAP connection UCM uses to query
Active Directory directly, kept deliberately separate from SSO's own LDAP
provider config (see models/ad_connector.py's module docstring for why).
"""
import logging

from flask import Blueprint, request

from auth.unified import require_auth
from models import db, ADConnectorConfig
from services.ad_connector import lookup
from services.audit_service import AuditService
from utils.datetime_utils import utc_now
from utils.db_transaction import safe_commit
from utils.response import success_response, error_response

logger = logging.getLogger(__name__)

bp = Blueprint('ad_connector_v2', __name__)

MAX_SERVER_LEN = 500
MAX_DN_LEN = 500


def _get_or_create():
    config = ADConnectorConfig.get_singleton()
    if config is None:
        config = ADConnectorConfig()
        db.session.add(config)
    return config


@bp.route('/api/v2/ad-connector', methods=['GET'])
@require_auth(['read:ad_connector'])
def get_config():
    """Get the Active Directory Connector configuration."""
    config = ADConnectorConfig.get_singleton()
    if config is None:
        return success_response(data=ADConnectorConfig().to_dict())
    return success_response(data=config.to_dict())


@bp.route('/api/v2/ad-connector', methods=['PUT'])
@require_auth(['write:ad_connector'])
def update_config():
    """Update the Active Directory Connector configuration (upsert)."""
    data = request.json or {}

    config = _get_or_create()

    if 'server' in data:
        server = (data['server'] or '').strip()
        if len(server) > MAX_SERVER_LEN:
            return error_response('server is too long', 400)
        config.server = server or None
    if 'port' in data:
        try:
            config.port = int(data['port']) if data['port'] not in (None, '') else 389
        except (TypeError, ValueError):
            return error_response('port must be an integer', 400)
    if 'use_ssl' in data:
        config.use_ssl = bool(data['use_ssl'])
    if 'verify_ssl' in data:
        config.verify_ssl = bool(data['verify_ssl'])
    if 'ca_bundle' in data:
        config.ca_bundle = (data['ca_bundle'] or '').strip() or None
    if 'base_dn' in data:
        base_dn = (data['base_dn'] or '').strip()
        if len(base_dn) > MAX_DN_LEN:
            return error_response('base_dn is too long', 400)
        config.base_dn = base_dn or None
    if 'bind_dn' in data:
        bind_dn = (data['bind_dn'] or '').strip()
        if len(bind_dn) > MAX_DN_LEN:
            return error_response('bind_dn is too long', 400)
        config.bind_dn = bind_dn or None
    if 'bind_password' in data and data['bind_password'] != '***':
        config.bind_password = data['bind_password'] or None
    if 'enabled' in data:
        config.enabled = bool(data['enabled'])

    config.updated_at = utc_now()

    try:
        ok, err = safe_commit(logger, 'Failed to update AD Connector configuration')
        if not ok:
            return err
    except Exception as e:
        # bind_password's setter raises if encryption is unavailable --
        # fail closed, never silently persist plaintext.
        db.session.rollback()
        logger.error('Failed to update AD Connector configuration: %s', e)
        return error_response('Failed to save configuration (encryption unavailable?)', 500)

    AuditService.log_action(
        action='ad_connector_config_update',
        resource_type='ad_connector',
        resource_name='AD Connector Configuration',
        details='Updated AD Connector configuration',
        success=True,
    )

    return success_response(data=config.to_dict(), message='AD Connector configuration saved')


@bp.route('/api/v2/ad-connector/test', methods=['POST'])
@require_auth(['write:ad_connector'])
def test_connection_inline():
    """Test connectivity using unsaved form data (before save)."""
    from types import SimpleNamespace

    data = request.json or {}
    if not data.get('server'):
        return error_response('server is required', 400)

    # Blank password means "unchanged" (form never re-sends the saved one),
    # not "use an empty password".
    bind_password = data.get('bind_password')
    if not bind_password:
        saved = ADConnectorConfig.get_singleton()
        if saved and saved.bind_password:
            bind_password = saved.bind_password

    cfg = SimpleNamespace(
        server=data.get('server'),
        port=int(data['port']) if data.get('port') else 389,
        use_ssl=bool(data.get('use_ssl')),
        verify_ssl=data.get('verify_ssl', True),
        ca_bundle=data.get('ca_bundle') or None,
        bind_dn=data.get('bind_dn'),
        bind_password=bind_password,
    )
    result = lookup.test_connection(cfg)
    if result.get('success'):
        return success_response(data=result, message=result.get('message'))
    return error_response(result.get('message', 'Connection test failed'), 400)


@bp.route('/api/v2/ad-connector/test-saved', methods=['POST'])
@require_auth(['write:ad_connector'])
def test_connection_saved():
    """Test connectivity using the saved configuration."""
    config = ADConnectorConfig.get_singleton()
    if config is None or not config.server:
        return error_response('AD Connector is not configured', 400)

    result = lookup.test_connection(config)
    config.last_test_at = utc_now()
    config.last_test_result = 'success' if result.get('success') else f"failed: {result.get('message')}"
    safe_commit(logger, 'Failed to record AD Connector test result')

    if result.get('success'):
        return success_response(data=result, message=result.get('message'))
    return error_response(result.get('message', 'Connection test failed'), 400)
