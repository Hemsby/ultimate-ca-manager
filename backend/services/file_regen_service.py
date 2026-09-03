"""
File Regeneration Service
Regenerates certificate/key files on disk from database at startup.
Ensures filesystem is consistent with database state.
"""
import base64
import logging
import os
from pathlib import Path

from config.settings import Config
from utils.file_naming import (
    ca_cert_path,
    ca_key_path,
    cert_cert_path,
    cert_key_path,
    cert_csr_path,
)

logger = logging.getLogger(__name__)


def mirror_private_key(path: Path, key_pem: bytes, *, context: str) -> bool:
    """Mirror a plaintext key only when database encryption is disabled.

    When encryption is enabled, any stale mirror at ``path`` is removed.
    Filesystem failures are recoverable and therefore logged without raising.
    """
    from security.encryption import key_encryption

    try:
        if key_encryption.is_enabled:
            path.unlink(missing_ok=True)
            logger.debug("Skipped plaintext key mirror for %s", context)
            return False

        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as key_file:
                fd = -1
                key_file.write(key_pem)
        finally:
            if fd >= 0:
                os.close(fd)
        return True
    except Exception as e:
        logger.warning("Could not mirror private key for %s: %s", context, e)
        return False


def write_cert_files(cert) -> None:
    """Write certificate, key, and CSR files for a Certificate object."""
    from utils.key_codec import load_pem_bytes

    Config.CERT_DIR.mkdir(parents=True, exist_ok=True)
    Config.PRIVATE_DIR.mkdir(parents=True, exist_ok=True)

    cert_path = cert_cert_path(cert)
    if not cert_path.exists() and cert.crt:
        try:
            cert_path.write_bytes(base64.b64decode(cert.crt))
        except Exception as e:
            logger.warning(f"Could not write cert file for {cert.descr}: {e}")

    if cert.prv:
        try:
            key_pem = load_pem_bytes(cert.prv, context=f"certificate {cert.id}")
            mirror_private_key(
                cert_key_path(cert), key_pem, context=f"certificate {cert.id}"
            )
        except Exception as e:
            logger.warning(f"Could not write key file for {cert.descr}: {e}")

    csr_path = cert_csr_path(cert)
    if not csr_path.exists() and cert.csr:
        try:
            csr_data = cert.csr
            csr_bytes = (
                csr_data.encode()
                if csr_data.startswith('-----BEGIN')
                else base64.b64decode(csr_data)
            )
            csr_path.write_bytes(csr_bytes)
        except Exception as e:
            logger.warning(f"Could not write CSR file for {cert.descr}: {e}")


def write_ca_files(ca) -> None:
    """Write certificate and key files for a CA object."""
    from utils.key_codec import load_pem_bytes

    Config.CA_DIR.mkdir(parents=True, exist_ok=True)
    Config.PRIVATE_DIR.mkdir(parents=True, exist_ok=True)

    cert_path = ca_cert_path(ca)
    if not cert_path.exists() and ca.crt:
        try:
            cert_path.write_bytes(base64.b64decode(ca.crt))
        except Exception as e:
            logger.warning(f"Could not write CA cert file for {ca.descr}: {e}")

    if ca.prv:
        try:
            key_pem = load_pem_bytes(ca.prv, context=f"CA {ca.id}")
            mirror_private_key(ca_key_path(ca), key_pem, context=f"CA {ca.id}")
        except Exception as e:
            logger.warning(f"Could not write CA key file for {ca.descr}: {e}")


def _handle_legacy_key(old_key: Path, new_key: Path, encryption_enabled: bool) -> int:
    """Remove or rename a legacy key mirror and return the rename count."""
    if not old_key.exists() or old_key == new_key:
        return 0
    if encryption_enabled:
        old_key.unlink(missing_ok=True)
        return 0
    if not new_key.exists():
        old_key.rename(new_key)
        return 1
    return 0


def regenerate_all_files():
    """Check and regenerate all certificate/key files from the database."""
    from models import CA, Certificate
    from security.encryption import key_encryption

    encryption_enabled = key_encryption.is_enabled
    for directory in [Config.CA_DIR, Config.CERT_DIR, Config.PRIVATE_DIR, Config.CRL_DIR]:
        directory.mkdir(parents=True, exist_ok=True)

    stats = {
        'ca_certs': 0,
        'ca_keys': 0,
        'certs': 0,
        'cert_keys': 0,
        'csrs': 0,
        'cleaned': 0,
        'keys_purged': 0,
    }

    for ca in CA.query.all():
        old_cert = Config.CA_DIR / f"{ca.refid}.crt"
        old_key = Config.PRIVATE_DIR / f"ca_{ca.refid}.key"
        new_cert = ca_cert_path(ca)
        new_key = ca_key_path(ca)

        if old_cert.exists() and not new_cert.exists() and old_cert != new_cert:
            old_cert.rename(new_cert)
            stats['cleaned'] += 1
        stats['cleaned'] += _handle_legacy_key(
            old_key, new_key, encryption_enabled
        )

        if not new_cert.exists() and ca.crt:
            try:
                new_cert.write_bytes(base64.b64decode(ca.crt))
                stats['ca_certs'] += 1
            except Exception as e:
                logger.warning(f"Failed to regenerate CA cert {ca.descr}: {e}")

        if ca.prv and (encryption_enabled or not new_key.exists()):
            try:
                from utils.key_codec import load_pem_bytes

                key_pem = load_pem_bytes(ca.prv, context=f"CA {ca.id}")
                if mirror_private_key(new_key, key_pem, context=f"CA {ca.id}"):
                    stats['ca_keys'] += 1
            except Exception as e:
                logger.warning(f"Failed to regenerate CA key {ca.descr}: {e}")

    for cert in Certificate.query.all():
        old_cert = Config.CERT_DIR / f"{cert.refid}.crt"
        old_csr = Config.CERT_DIR / f"{cert.refid}.csr"
        old_key = Config.PRIVATE_DIR / f"cert_{cert.refid}.key"
        new_cert = cert_cert_path(cert)
        new_csr = cert_csr_path(cert)
        new_key = cert_key_path(cert)

        if old_cert.exists() and not new_cert.exists() and old_cert != new_cert:
            old_cert.rename(new_cert)
            stats['cleaned'] += 1
        if old_csr.exists() and not new_csr.exists() and old_csr != new_csr:
            old_csr.rename(new_csr)
            stats['cleaned'] += 1
        stats['cleaned'] += _handle_legacy_key(
            old_key, new_key, encryption_enabled
        )

        if not new_cert.exists() and cert.crt:
            try:
                new_cert.write_bytes(base64.b64decode(cert.crt))
                stats['certs'] += 1
            except Exception as e:
                logger.warning(f"Failed to regenerate cert {cert.descr}: {e}")

        if not new_csr.exists() and cert.csr:
            try:
                csr_data = cert.csr
                csr_bytes = (
                    csr_data.encode('utf-8')
                    if csr_data.startswith('-----BEGIN')
                    else base64.b64decode(csr_data)
                )
                new_csr.write_bytes(csr_bytes)
                stats['csrs'] += 1
            except Exception as e:
                logger.warning(f"Failed to regenerate CSR {cert.descr}: {e}")

        if cert.prv and (encryption_enabled or not new_key.exists()):
            try:
                from utils.key_codec import load_pem_bytes

                key_pem = load_pem_bytes(cert.prv, context=f"certificate {cert.id}")
                if mirror_private_key(
                    new_key, key_pem, context=f"certificate {cert.id}"
                ):
                    stats['cert_keys'] += 1
            except Exception as e:
                logger.warning(f"Failed to regenerate cert key {cert.descr}: {e}")

    if sum(stats.values()) > 0:
        logger.info(f"File regeneration: {stats}")
    else:
        logger.info("File regeneration: all files up to date")

    return stats
