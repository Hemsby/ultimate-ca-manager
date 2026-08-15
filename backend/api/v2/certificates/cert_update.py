"""Certificate metadata update route (rename)"""
import logging
from flask import request
from auth.unified import require_auth
from utils.db_transaction import safe_commit
from utils.response import success_response, error_response
from models import Certificate, db
from services.audit_service import AuditService
from . import bp

logger = logging.getLogger(__name__)


@bp.route('/api/v2/certificates/<int:cert_id>', methods=['PATCH'])
@require_auth(['write:certificates'])
def update_certificate(cert_id):
    """Update certificate metadata. Only the display name (descr) is mutable."""
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        return error_response('Certificate not found', 404)

    data = request.get_json(silent=True)
    if not data or 'descr' not in data:
        return error_response('descr is required', 400)

    descr = data['descr']
    if not isinstance(descr, str) or not descr.strip():
        return error_response('descr must be a non-empty string', 400)
    descr = descr.strip()
    if len(descr) > 255:
        return error_response('descr must be 255 characters or fewer', 400)

    old_descr = cert.descr
    cert.descr = descr
    ok, err = safe_commit(logger, "Failed to update certificate")
    if not ok:
        return err

    AuditService.log_action(
        action='certificate_renamed',
        resource_type='certificate',
        resource_id=cert.id,
        resource_name=descr,
        details=f'Renamed certificate: "{old_descr}" -> "{descr}"',
        success=True
    )

    return success_response(data=cert.to_dict(), message='Certificate updated')
