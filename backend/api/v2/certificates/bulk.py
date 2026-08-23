"""
Certificates Bulk Operations Routes
/api/v2/certificates/bulk/* - Bulk revoke, renew, delete, export
"""

import base64
import json
import logging
import os
import subprocess
import tempfile
from datetime import timedelta
from flask import request, g, Response
from auth.unified import require_auth, has_permission
from sqlalchemy import or_
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from models import Certificate, CA, RevokedSerial, db
from services.cert_service import CertificateService
from services.audit_service import AuditService
from services.ocsp_service import OCSPService
from utils.db_transaction import safe_commit
from utils.response import success_response, error_response
from utils.datetime_utils import utc_now
from utils.upn_san import extract_upns_from_san_list
from . import bp

logger = logging.getLogger(__name__)


@bp.route('/api/v2/certificates/bulk/revoke', methods=['POST'])
@require_auth(['write:certificates'])
def bulk_revoke_certificates():
    """Bulk revoke certificates"""

    data = request.get_json()
    if not data or not data.get('ids'):
        return error_response('ids array required', 400)

    ids = data['ids']
    reason = data.get('reason', 'unspecified')
    username = g.current_user.username if hasattr(g, 'current_user') else 'system'

    results = {'success': [], 'failed': []}
    for cert_id in ids:
        try:
            cert = db.session.get(Certificate, cert_id)
            if not cert:
                results['failed'].append({'id': cert_id, 'error': 'Not found'})
                continue
            if cert.revoked:
                results['failed'].append({'id': cert_id, 'error': 'Already revoked'})
                continue
            CertificateService.revoke_certificate(cert_id=cert_id, reason=reason, username=username)
            results['success'].append(cert_id)
        except Exception as e:
            logger.error(f"Bulk revoke failed for cert {cert_id}: {e}")
            results['failed'].append({'id': cert_id, 'error': 'Revocation failed'})

    AuditService.log_action(
        action='certificates_bulk_revoked',
        resource_type='certificate',
        resource_id=','.join(str(i) for i in results['success']),
        resource_name=f'{len(results["success"])} certificates',
        details=f'Bulk revoked {len(results["success"])} certificates (reason: {reason})',
        success=True
    )

    return success_response(data=results, message=f'{len(results["success"])} certificates revoked')


@bp.route('/api/v2/certificates/bulk/renew', methods=['POST'])
@require_auth(['write:certificates'])
def bulk_renew_certificates():
    """Bulk renew certificates"""

    data = request.get_json()
    if not data or not data.get('ids'):
        return error_response('ids array required', 400)

    ids = data['ids']
    results = {'success': [], 'failed': []}

    for cert_id in ids:
        try:
            cert = db.session.get(Certificate, cert_id)
            if not cert:
                results['failed'].append({'id': cert_id, 'error': 'Not found'})
                continue
            if not cert.crt:
                results['failed'].append({'id': cert_id, 'error': 'No certificate data'})
                continue

            ca = CA.query.filter_by(refid=cert.caref).first()
            if not ca or not ca.has_private_key:
                results['failed'].append({'id': cert_id, 'error': 'Issuing CA not found or no private key'})
                continue
            if ca.offline:
                results['failed'].append({'id': cert_id, 'error': 'CA is offline'})
                continue

            orig_cert_pem = base64.b64decode(cert.crt)
            orig_cert = x509.load_pem_x509_certificate(orig_cert_pem, default_backend())
            ca_cert_pem = base64.b64decode(ca.crt)
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
            from services.hsm.ca_key_loader import get_ca_signing_key
            ca_key = get_ca_signing_key(ca)

            orig_pub_key = orig_cert.public_key()
            if isinstance(orig_pub_key, rsa.RSAPublicKey):
                new_key = rsa.generate_private_key(65537, orig_pub_key.key_size, default_backend())
            elif isinstance(orig_pub_key, ec.EllipticCurvePublicKey):
                new_key = ec.generate_private_key(orig_pub_key.curve, default_backend())
            else:
                new_key = rsa.generate_private_key(65537, 2048, default_backend())

            orig_duration = orig_cert.not_valid_after_utc - orig_cert.not_valid_before_utc
            validity_days = orig_duration.days if orig_duration.days > 0 else 365
            if validity_days > 3650:
                validity_days = 3650
            now = utc_now()
            not_after = now + timedelta(days=validity_days)
            ca_not_after = ca_cert.not_valid_after_utc.replace(tzinfo=None)
            if not_after > ca_not_after:
                not_after = ca_not_after

            try:
                _bulk_sans = list(
                    orig_cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    ).value
                )
            except x509.ExtensionNotFound:
                _bulk_sans = None
            try:
                from services.trust_store.constraints_mixin import validate_name_constraints
                validate_name_constraints(ca_cert, orig_cert.subject, _bulk_sans,
                                          renewal_of=orig_cert)
            except ValueError as exc:
                results['failed'].append({'id': cert_id, 'error': f'Name constraints: {exc}'})
                continue

            builder = (x509.CertificateBuilder()
                .subject_name(orig_cert.subject)
                .issuer_name(ca_cert.subject)
                .public_key(new_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(not_after))

            for ext in orig_cert.extensions:
                if ext.oid in (ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.SUBJECT_KEY_IDENTIFIER):
                    continue
                try:
                    builder = builder.add_extension(ext.value, ext.critical)
                except Exception:
                    pass

            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(new_key.public_key()), critical=False)
            try:
                builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            except Exception:
                pass

            new_cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

            username = g.current_user.username if hasattr(g, 'current_user') else 'system'

            # Snapshot old cert fields for RevokedSerial record
            old_serial = cert.serial_number
            old_valid_to = cert.valid_to
            old_caref = cert.caref

            new_serial_hex = format(new_cert.serial_number, 'x')
            new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            new_key_pem = new_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode('utf-8')

            # Extract SKI/AKI from new cert
            try:
                ski_ext = new_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                new_ski = ':'.join(f'{b:02x}' for b in ski_ext.value.digest)
            except x509.ExtensionNotFound:
                new_ski = None
            try:
                aki_ext = new_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                new_aki = ':'.join(f'{b:02x}' for b in aki_ext.value.key_identifier) if aki_ext.value.key_identifier else None
            except x509.ExtensionNotFound:
                new_aki = None

            # Extract SANs from new cert.
            # x509 GeneralName objects expose no `.type` attribute — the
            # canonical discrimination is isinstance() (see
            # utils/cert_extensions._parse_san).
            new_san_dns, new_san_ip, new_san_email, new_san_uri, new_san_upn = [], [], [], [], []
            try:
                san_ext = new_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_entries = list(san_ext.value)
                for name in san_entries:
                    if isinstance(name, x509.DNSName):
                        new_san_dns.append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        new_san_ip.append(str(name.value))
                    elif isinstance(name, x509.RFC822Name):
                        new_san_email.append(name.value)
                    elif isinstance(name, x509.UniformResourceIdentifier):
                        new_san_uri.append(name.value)
                # OtherName UPNs are DER-encoded UTF8Strings — decode via the
                # shared helper instead of treating the DER blob as raw UTF-8.
                new_san_upn = extract_upns_from_san_list(san_entries)
            except x509.ExtensionNotFound:
                pass

            new_pub = new_cert.public_key()
            if isinstance(new_pub, rsa.RSAPublicKey):
                key_algo_str = f'RSA {new_pub.key_size}'
            elif isinstance(new_pub, ec.EllipticCurvePublicKey):
                key_algo_str = f'EC {new_pub.curve.name}'
            else:
                key_algo_str = 'Unknown'

            # --- Insert RevokedSerial for the old serial ---
            # certificate_id is preserved so there is a direct FK link from
            # every previous serial back to the certificate row.
            #
            # Both the RevokedSerial insert and the in-place cert update are
            # in the same session — if the commit fails, safe_commit rolls
            # back both, leaving the certificate and revocation state unchanged.
            if old_caref and old_serial:
                existing_rs = RevokedSerial.query.filter_by(
                    caref=old_caref,
                    serial_number=old_serial,
                ).first()
                if existing_rs:
                    existing_rs.revoked_at = now
                    existing_rs.revoke_reason = 'superseded'
                    existing_rs.valid_to = old_valid_to or (now + timedelta(days=365))
                    existing_rs.certificate_id = cert_id
                else:
                    revoked_record = RevokedSerial(
                        caref=old_caref,
                        serial_number=old_serial,
                        revoked_at=now,
                        revoke_reason='superseded',
                        valid_to=old_valid_to or (now + timedelta(days=365)),
                        certificate_id=cert_id,
                    )
                    db.session.add(revoked_record)

            # --- In-place update of the existing certificate row ---
            # id, refid, created_at, created_by are preserved.
            # renewed_at is set to now; renewed_times is incremented.
            cert.crt = base64.b64encode(new_cert_pem.encode()).decode()
            cert.prv = base64.b64encode(new_key_pem.encode()).decode()
            cert.serial_number = new_serial_hex
            cert.aki = new_aki
            cert.ski = new_ski
            cert.valid_from = now
            cert.valid_to = not_after
            cert.key_algo = key_algo_str
            cert.issuer = ca_cert.subject.rfc4514_string()
            cert.san_dns = json.dumps(new_san_dns) if new_san_dns else None
            cert.san_ip = json.dumps([str(ip) for ip in new_san_ip]) if new_san_ip else None
            cert.san_email = json.dumps(new_san_email) if new_san_email else None
            cert.san_uri = json.dumps(new_san_uri) if new_san_uri else None
            cert.san_upn = json.dumps(new_san_upn) if new_san_upn else None
            cert.revoked = False
            cert.revoked_at = None
            cert.revoke_reason = None
            cert.invalidity_at = None
            cert.renewed_at = now
            cert.renewed_times = (cert.renewed_times or 0) + 1

            # --- Atomic commit: RevokedSerial + in-place cert update together ---
            # If this fails, both changes are rolled back — the certificate
            # retains its old serial, crt, prv, revoked state, and the
            # RevokedSerial is not persisted. No partial state is left behind.
            ok, err = safe_commit(logger, f"Bulk renew failed for cert {cert_id}")
            if not ok:
                # safe_commit already called db.session.rollback()
                results['failed'].append({'id': cert_id, 'error': 'Renewal failed'})
                continue

            # Overwrite cert/key files on disk (filenames based on CN-slug + refid[:8], unchanged)
            try:
                from utils.file_naming import cert_cert_path, cert_key_path
                _cert_path = cert_cert_path(cert)
                _key_path = cert_key_path(cert)
                _cert_path.parent.mkdir(parents=True, exist_ok=True)
                _key_path.parent.mkdir(parents=True, exist_ok=True)
                _cert_path.write_bytes(new_cert_pem.encode())
                _key_path.write_bytes(new_key_pem.encode())
                try:
                    _key_path.chmod(0o600)
                except (OSError, PermissionError):
                    pass
            except Exception as e:
                logger.warning(f"Failed to write cert/key files for renewed cert {cert_id}: {e}")

            # Invalidate OCSP cache for the old serial
            try:
                OCSPService.invalidate_cached_responses(old_serial, ca_id=ca.id)
            except Exception as e:
                logger.warning(f"Failed to invalidate OCSP cache for old serial {old_serial}: {e}")

            results['success'].append(cert_id)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Bulk renew failed for cert {cert_id}: {e}")
            results['failed'].append({'id': cert_id, 'error': 'Renewal failed'})

    AuditService.log_action(
        action='certificates_bulk_renewed',
        resource_type='certificate',
        resource_id=','.join(str(i) for i in results['success']),
        resource_name=f'{len(results["success"])} certificates',
        details=f'Bulk renewed {len(results["success"])} certificates',
        success=True
    )

    return success_response(data=results, message=f'{len(results["success"])} certificates renewed')


@bp.route('/api/v2/certificates/bulk/delete', methods=['POST'])
@require_auth(['delete:certificates'])
def bulk_delete_certificates():
    """Bulk delete certificates"""

    data = request.get_json()
    if not data or not data.get('ids'):
        return error_response('ids array required', 400)

    ids = data['ids']
    username = g.current_user.username if hasattr(g, 'current_user') else 'system'
    results = {'success': [], 'failed': []}

    for cert_id in ids:
        try:
            cert = db.session.get(Certificate, cert_id)
            if not cert:
                results['failed'].append({'id': cert_id, 'error': 'Not found'})
                continue

            # Prevent deletion of valid (non-revoked, non-expired) certificates.
            if cert.crt and not cert.revoked:
                if not cert.valid_to or cert.valid_to >= utc_now():
                    results['failed'].append({
                        'id': cert_id,
                        'error': 'Cannot delete a valid certificate — revoke it first',
                    })
                    continue

            # Delegate to the service so cert/key/csr files on disk are
            # unlinked along with the DB row instead of leaving them orphaned.
            if CertificateService.delete_certificate(cert_id=cert_id, username=username):
                results['success'].append(cert_id)
            else:
                results['failed'].append({'id': cert_id, 'error': 'Deletion failed'})
        except Exception as e:
            db.session.rollback()
            logger.error(f"Bulk delete failed for cert {cert_id}: {e}")
            results['failed'].append({'id': cert_id, 'error': 'Deletion failed'})

    AuditService.log_action(
        action='certificates_bulk_deleted',
        resource_type='certificate',
        resource_id=','.join(str(i) for i in results['success']),
        resource_name=f'{len(results["success"])} certificates',
        details=f'Bulk deleted {len(results["success"])} certificates',
        success=True
    )

    return success_response(data=results, message=f'{len(results["success"])} certificates deleted')


@bp.route('/api/v2/certificates/bulk/export', methods=['POST'])
@require_auth(['read:certificates'])
def bulk_export_certificates():
    """Export selected certificates"""

    data = request.get_json()
    if not data or not data.get('ids'):
        return error_response('ids array required', 400)

    export_format = data.get('format', 'pem').lower()
    certs = Certificate.query.filter(Certificate.id.in_(data['ids']), Certificate.crt.isnot(None)).all()

    if not certs:
        return error_response('No certificates found', 404)

    try:
        if export_format == 'pem':
            pem_data = b''
            for cert in certs:
                pem_data += base64.b64decode(cert.crt)
                if not pem_data.endswith(b'\n'):
                    pem_data += b'\n'
            return Response(pem_data, mimetype='application/x-pem-file',
                headers={'Content-Disposition': 'attachment; filename="certificates.pem"'})
        elif export_format in ('pkcs7', 'p7b'):
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                for cert in certs:
                    f.write(base64.b64decode(cert.crt))
                    f.write(b'\n')
                pem_file = f.name
            try:
                p7b_output = subprocess.check_output(
                    ['openssl', 'crl2pkcs7', '-nocrl', '-certfile', pem_file, '-outform', 'DER'],
                    stderr=subprocess.DEVNULL, timeout=30)
                return Response(p7b_output, mimetype='application/x-pkcs7-certificates',
                    headers={'Content-Disposition': 'attachment; filename="certificates.p7b"'})
            finally:
                os.unlink(pem_file)
        else:
            return error_response('Supported formats: pem, p7b', 400)
    except Exception as e:
        logger.error(f"Bulk export failed: {e}")
        return error_response('Export failed', 500)
