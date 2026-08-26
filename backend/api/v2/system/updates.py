"""
System Updates Operations
"""

from . import bp
from flask import request
from auth.unified import require_auth
from utils.response import success_response, error_response
from services.audit_service import AuditService
import os
import logging

logger = logging.getLogger(__name__)


@bp.route('/api/v2/system/updates/check', methods=['GET'])
@require_auth(['admin:system'])
def check_updates():
    """Check for available updates"""
    try:
        from services.updates import check_for_updates

        include_prereleases = request.args.get('include_prereleases', 'false').lower() == 'true'
        include_dev = request.args.get('include_dev', 'false').lower() == 'true'
        force = request.args.get('force', 'false').lower() == 'true'
        result = check_for_updates(include_prereleases=include_prereleases, include_dev=include_dev, force=force)
        result['can_auto_update'] = os.getenv('UCM_DOCKER') != '1'

        return success_response(data=result)
    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        return error_response("Failed to check for updates", 500)


@bp.route('/api/v2/system/updates/install', methods=['POST'])
@require_auth(['admin:system'])
def install_update():
    """Download and install an update"""
    if os.getenv('UCM_DOCKER') == '1':
        return error_response(
            "Auto-update is not available in Docker. Pull the new image instead: "
            "docker pull ghcr.io/neyslim/ultimate-ca-manager:latest", 400
        )

    try:
        from services.updates import (
            check_for_updates, download_update, fetch_expected_sha256,
            install_update as do_install,
        )

        # Get update info
        include_prereleases = request.json.get('include_prereleases', False)
        include_dev = request.json.get('include_dev', False)
        update_info = check_for_updates(include_prereleases=include_prereleases, include_dev=include_dev)

        if not update_info.get('update_available'):
            return error_response("No update available", 400)

        if not update_info.get('download_url'):
            return error_response("No download URL available for this platform", 400)

        # Resolve the published SHA256. A release that publishes one must
        # verify — a fetch failure or a missing entry refuses the install
        # rather than silently downgrading to unverified.
        expected_sha256 = None
        checksum_note = 'no checksum published for this release'
        if update_info.get('checksum_url'):
            try:
                expected_sha256 = fetch_expected_sha256(
                    update_info['checksum_url'], update_info['package_name']
                )
            except Exception as e:
                logger.error(f"Checksum fetch failed: {e}")
                return error_response(
                    "Could not retrieve the release checksum — install refused", 502
                )
            if not expected_sha256:
                return error_response(
                    "Release checksum does not cover this package — install refused", 502
                )
            checksum_note = 'SHA256 verified'

        # Download (verifies the digest on the fly when one is expected)
        package_path = download_update(
            update_info['download_url'],
            update_info['package_name'],
            expected_sha256=expected_sha256,
        )

        # Install (this will restart the service)
        do_install(package_path)

        # Log the update
        AuditService.log_action(
            action='settings_update',
            resource_type='system',
            resource_id='ucm',
            resource_name='UCM Update',
            details=(
                f"Updated from {update_info['current_version']} to "
                f"{update_info['latest_version']} ({checksum_note})"
            )
        )

        return success_response(
            message=f"Update to {update_info['latest_version']} initiated. Service will restart shortly."
        )
    except Exception as e:
        logger.error(f"Update failed: {e}")
        return error_response("Update failed", 500)


@bp.route('/api/v2/system/updates/settings', methods=['GET'])
@require_auth(['admin:system'])
def get_update_settings():
    """Get update automation settings (#301)"""
    from services.updates import get_update_settings as read_settings

    data = read_settings()
    data['can_auto_update'] = os.getenv('UCM_DOCKER') != '1'
    return success_response(data=data)


@bp.route('/api/v2/system/updates/settings', methods=['PATCH'])
@require_auth(['admin:system'])
def update_update_settings():
    """Update the update automation settings (#301)"""
    from services.updates import (
        UPDATE_CHANNEL_KEY, AUTO_UPDATE_ENABLED_KEY, AUTO_UPDATE_HOUR_KEY,
        _cfg_set, get_update_settings as read_settings,
    )

    data = request.json or {}

    if 'channel' in data:
        if data['channel'] not in ('stable', 'rc'):
            return error_response("channel must be 'stable' or 'rc'", 400)
    if 'hour' in data:
        if not isinstance(data['hour'], int) or not 0 <= data['hour'] <= 23:
            return error_response("hour must be an integer between 0 and 23", 400)
    if 'auto_install' in data and not isinstance(data['auto_install'], bool):
        return error_response("auto_install must be a boolean", 400)
    if data.get('auto_install') and os.getenv('UCM_DOCKER') == '1':
        return error_response(
            "Auto-update is not available in Docker. Pull the new image instead.", 400
        )

    if 'channel' in data:
        _cfg_set(UPDATE_CHANNEL_KEY, data['channel'])
    if 'hour' in data:
        _cfg_set(AUTO_UPDATE_HOUR_KEY, str(data['hour']))
    if 'auto_install' in data:
        _cfg_set(AUTO_UPDATE_ENABLED_KEY, 'true' if data['auto_install'] else 'false')

    AuditService.log_action(
        action='settings_update', resource_type='system', resource_id='ucm',
        resource_name='UCM Update Settings',
        details=f"Update automation settings changed: {sorted(data.keys())}",
        success=True,
    )
    result = read_settings()
    result['can_auto_update'] = os.getenv('UCM_DOCKER') != '1'
    return success_response(data=result, message='Update settings saved')


@bp.route('/api/v2/system/updates/version', methods=['GET'])
def get_version():
    """Get current version info (public endpoint)"""
    from services.updates import get_current_version

    return success_response(data={
        'version': get_current_version()
    })
