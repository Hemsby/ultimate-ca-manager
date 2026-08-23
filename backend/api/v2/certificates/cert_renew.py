"""Certificate renewal route"""
import logging
import base64
import json
from datetime import timedelta
from flask import request, g
from auth.unified import require_auth
from utils.db_transaction import safe_commit
from utils.response import success_response, error_response
from models import Certificate, CA, RevokedSerial, db
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from services.audit_service import AuditService
from services.ocsp_service import OCSPService
from websocket.emitters import on_certificate_renewed
from utils.datetime_utils import utc_now
from utils.upn_san import extract_upns_from_san_list
from . import bp

logger = logging.getLogger(__name__)


@bp.route('/api/v2/certificates/<int:cert_id>/renew', methods=['POST'])
@require_auth(['write:certificates'])
def renew_certificate(cert_id):
    """
    Renew certificate - In-place update with old serial revocation.

    The certificate row (id, refid, created_at) is preserved. The old serial
    is recorded in revoked_serials with reason 'superseded' and
    certificate_id pointing back to this row, so the CRL query can
    distinguish between the current serial (good) and previous serials
    (revoked/superseded). renewed_at is set to utc_now().
    """

    # Get original certificate
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        return error_response('Certificate not found', 404)

    if not cert.crt:
        return error_response('Certificate data not available', 400)

    # Certificates issued by a Microsoft AD CS connection can't be re-signed
    # locally (the issuing CA's key lives on the Windows CA) — resubmit the
    # original CSR through the connector instead.
    if cert.source == 'msca':
        return _renew_msca_certificate(cert)

    # Get the CA that issued this certificate
    # Try by refid first, then by matching issuer to CA subject
    ca = CA.query.filter_by(refid=cert.caref).first()
    if not ca and cert.issuer:
        # Try to find CA by matching subject to certificate's issuer
        ca = CA.query.filter(CA.subject == cert.issuer).first()
        if not ca:
            # Try partial match (issuer might have different formatting)
            for potential_ca in CA.query.all():
                if potential_ca.subject and cert.issuer:
                    # Extract CN from both and compare
                    ca_cn = potential_ca.subject.split('CN=')[1].split(',')[0] if 'CN=' in potential_ca.subject else None
                    cert_issuer_cn = cert.issuer.split('CN=')[1].split(',')[0] if 'CN=' in cert.issuer else None
                    if ca_cn and cert_issuer_cn and ca_cn == cert_issuer_cn:
                        ca = potential_ca
                        break

    if not ca:
        return error_response('Issuing CA not found. The CA that signed this certificate is not in the system.', 404)

    if not ca.has_private_key:
        return error_response('CA private key not available. Cannot renew without CA private key.', 400)
    if ca.offline:
        return error_response('CA is offline; restore it before renewing', 400)

    try:
        # Load original certificate
        orig_cert_pem = base64.b64decode(cert.crt)
        orig_cert = x509.load_pem_x509_certificate(orig_cert_pem, default_backend())

        # Load CA certificate and key
        ca_cert_pem = base64.b64decode(ca.crt)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
        from services.hsm.ca_key_loader import get_ca_signing_key
        ca_key = get_ca_signing_key(ca)

        # Generate new key pair (same type and size as original)
        orig_pub_key = orig_cert.public_key()
        if isinstance(orig_pub_key, rsa.RSAPublicKey):
            key_size = orig_pub_key.key_size
            new_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif isinstance(orig_pub_key, ec.EllipticCurvePublicKey):
            curve = orig_pub_key.curve
            new_key = ec.generate_private_key(curve, default_backend())
        else:
            # Default to RSA 2048
            new_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

        # Calculate new validity (same duration as original, starting now; cap 1..3650)
        orig_duration = orig_cert.not_valid_after_utc - orig_cert.not_valid_before_utc
        validity_days = orig_duration.days if orig_duration.days > 0 else 365
        if validity_days > 3650:
            validity_days = 3650

        now = utc_now()
        not_before = now
        not_after = now + timedelta(days=validity_days)
        # Don't exceed CA expiration
        ca_not_after = ca_cert.not_valid_after_utc.replace(tzinfo=None)
        if not_after > ca_not_after:
            not_after = ca_not_after

        # Re-validate the subject/SANs against the CA chain's NameConstraints
        # before re-issuing: the CA's constraints may have been tightened since
        # the original certificate was signed, so a renewal must not blindly
        # reproduce a now-out-of-scope name (RFC 5280 §4.2.1.10).
        try:
            renew_sans = list(
                orig_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value
            )
        except x509.ExtensionNotFound:
            renew_sans = None
        try:
            from services.trust_store.constraints_mixin import validate_name_constraints
            # renewal_of grants renewal-at-par: names the certificate already
            # carries stay renewable even if the CA's constraints tightened
            # (or started being enforced) after it was issued.
            validate_name_constraints(ca_cert, orig_cert.subject, renew_sans,
                                      renewal_of=orig_cert)
        except ValueError as exc:
            logger.info(f"Renewal rejected by CA NameConstraints: {exc}")
            return error_response(f"Renewal violates CA name constraints: {exc}", 400)

        # Build new certificate with same subject and extensions
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(orig_cert.subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(new_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)

        # Copy extensions from original certificate
        for ext in orig_cert.extensions:
            # Skip Authority Key Identifier (will be regenerated)
            if ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                continue
            # Skip Subject Key Identifier (will be regenerated for new key)
            if ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                continue
            try:
                builder = builder.add_extension(ext.value, ext.critical)
            except Exception:
                # Skip extensions that can't be copied
                pass

        # Add Subject Key Identifier for new key
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(new_key.public_key()),
            critical=False
        )

        # Add Authority Key Identifier
        try:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False
            )
        except Exception:
            pass

        # Sign new certificate
        new_cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

        # Serialize to PEM
        new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        new_key_pem = new_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        username = g.current_user.username if hasattr(g, 'current_user') else 'system'

        # --- Snapshot old cert fields for RevokedSerial record ---
        old_serial = cert.serial_number
        old_valid_to = cert.valid_to
        old_caref = cert.caref

        new_serial_hex = format(new_cert.serial_number, 'x')

        # Extract SANs from the new certificate.
        # x509 GeneralName objects (DNSName, IPAddress, ...) expose no `.type`
        # attribute — the canonical way to discriminate them is isinstance()
        # (see utils/cert_extensions._parse_san and services/import_service).
        san_dns = []
        san_ip = []
        san_email = []
        san_uri = []
        san_upn = []
        try:
            san_ext = new_cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_entries = list(san_ext.value)
            for name in san_entries:
                if isinstance(name, x509.DNSName):
                    san_dns.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_ip.append(str(name.value))
                elif isinstance(name, x509.RFC822Name):
                    san_email.append(name.value)
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_uri.append(name.value)
            # OtherName UPNs are DER-encoded UTF8Strings — decode via the
            # shared helper instead of treating the DER blob as raw UTF-8.
            san_upn = extract_upns_from_san_list(san_entries)
        except x509.ExtensionNotFound:
            pass

        # Extract SKI
        try:
            ski_ext = new_cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )
            new_ski = ':'.join(f'{b:02x}' for b in ski_ext.value.digest)
        except x509.ExtensionNotFound:
            new_ski = None

        # Extract AKI
        try:
            aki_ext = new_cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            new_aki = ':'.join(f'{b:02x}' for b in aki_ext.value.key_identifier) if aki_ext.value.key_identifier else None
        except x509.ExtensionNotFound:
            new_aki = None

        # Determine key algo string
        new_pub = new_cert.public_key()
        if isinstance(new_pub, rsa.RSAPublicKey):
            key_algo_str = f'RSA {new_pub.key_size}'
        elif isinstance(new_pub, ec.EllipticCurvePublicKey):
            key_algo_str = f'EC {new_pub.curve.name}'
        else:
            key_algo_str = 'Unknown'

        # --- Insert RevokedSerial for the old serial (before updating the cert) ---
        # The certificate_id is preserved so there is a direct FK link from
        # every previous serial back to the certificate row. The CRL query
        # checks serial_number match to distinguish the current serial (good)
        # from superseded serials (revoked).
        #
        # Both the RevokedSerial insert and the in-place cert update are in
        # the same session — if the commit fails, safe_commit rolls back both,
        # leaving the certificate and revocation state unchanged.
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
        cert.valid_from = not_before
        cert.valid_to = not_after
        cert.key_algo = key_algo_str
        cert.issuer = ca_cert.subject.rfc4514_string()
        cert.san_dns = json.dumps(san_dns) if san_dns else None
        cert.san_ip = json.dumps([str(ip) for ip in san_ip]) if san_ip else None
        cert.san_email = json.dumps(san_email) if san_email else None
        cert.san_uri = json.dumps(san_uri) if san_uri else None
        cert.san_upn = json.dumps(san_upn) if san_upn else None
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
        ok, err = safe_commit(logger, "Failed to renew certificate")
        if not ok:
            # safe_commit already called db.session.rollback()
            return err

        # --- Overwrite cert/key files on disk ---
        # The filenames are based on CN-slug + refid[:8], both unchanged
        # since we're doing an in-place update.
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

        # --- Invalidate OCSP cache for the old serial ---
        # The old serial is now revoked (superseded); new OCSP responses must
        # reflect this immediately.
        try:
            OCSPService.invalidate_cached_responses(old_serial, ca_id=ca.id)
        except Exception as e:
            logger.warning(f"Failed to invalidate OCSP cache for old serial {old_serial}: {e}")

        # --- Auto-generate CRL if CA has CDP enabled ---
        if ca.cdp_enabled:
            try:
                from services.crl_service import CRLService
                CRLService.generate_crl(ca.id, username=username)
            except Exception as e:
                logger.warning(f"Failed to auto-generate CRL after renewal: {e}")

        # Audit log
        try:
            AuditService.log_action(
                action='certificate_renewed',
                resource_type='certificate',
                resource_id=str(cert_id),
                resource_name=cert.subject,
                details=f"Renewed until {not_after.isoformat()} (old serial: {old_serial}, new serial: {new_serial_hex})",
                user_id=g.current_user.id if hasattr(g, 'current_user') else None
            )
        except Exception:
            pass

        cert_dict = cert.to_dict()
        cert_caref = cert.caref
        from services.webhook_service import emit_cert_renewed
        emit_cert_renewed(cert_dict, ca_refid=cert_caref, actor=username)

        return success_response(
            data=cert_dict,
            message='Certificate renewed successfully'
        )

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to renew certificate {cert_id}: {e}")
        return error_response('Failed to renew certificate', 500)


def _renew_msca_certificate(cert):
    """Renew a Microsoft-CA-issued certificate through its AD CS connection."""
    from api.v2.msca import renew_via_msca  # deferred: avoids circular import

    username = g.current_user.username if hasattr(g, 'current_user') else 'system'
    cert_id = cert.id

    try:
        result = renew_via_msca(cert, username=username)
    except PermissionError as e:
        return error_response(str(e), 403)
    except ValueError as e:
        logger.error(f"Cannot renew certificate {cert_id} via Microsoft CA: {e}")
        return error_response(str(e), 400)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to renew certificate {cert_id} via Microsoft CA: {e}", exc_info=True)
        return error_response('Failed to renew certificate via Microsoft CA', 500)

    if result.get('status') == 'pending':
        return success_response(
            data=cert.to_dict(),
            message='Renewal submitted to Microsoft CA — pending CA manager approval',
            meta={'msca_status': 'pending'}
        )

    # Issued: the certificate row was updated in place by the import
    try:
        AuditService.log_action(
            action='certificate_renewed',
            resource_type='certificate',
            resource_id=str(cert_id),
            resource_name=cert.subject,
            details=f"Renewed via Microsoft CA until {cert.valid_to.isoformat() if cert.valid_to else 'unknown'}",
            user_id=g.current_user.id if hasattr(g, 'current_user') else None
        )
    except Exception:
        pass

    cert_dict = cert.to_dict()
    cert_caref = cert.caref
    from services.webhook_service import emit_cert_renewed
    emit_cert_renewed(cert_dict, ca_refid=cert_caref, actor=username)

    return success_response(
        data=cert_dict,
        message='Certificate renewed by Microsoft CA',
        meta={'msca_status': 'issued'}
    )
