"""
Encryption utilities for sensitive data in database
Uses Fernet symmetric encryption with key from environment
"""

import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from functools import lru_cache

logger = logging.getLogger(__name__)


def _get_encryption_key() -> bytes:
    """
    Get or generate encryption key from environment.
    Key is derived from UCM_DB_ENCRYPTION_KEY or a default based on machine ID.
    """
    key = os.environ.get('UCM_DB_ENCRYPTION_KEY')

    if key:
        # Use provided key (should be base64-encoded 32 bytes)
        return key.encode()

    # No explicit key. The fallback below derives one from the machine id with
    # a salt that is a constant in this source file — so anyone holding a copy
    # of the database AND /etc/machine-id (world-readable, and routinely
    # captured in backups and VM images) can reconstruct the key and decrypt
    # every integration secret: DNS-provider credentials, LDAP/ADCS/WinRM
    # passwords, SMTP and OAuth secrets, SSO client secrets, webhook secrets,
    # ACME EAB keys and HSM credentials.
    #
    # The derivation is kept for backward compatibility — changing it would
    # make existing encrypted rows undecryptable — but it is now loud, and
    # deployments can refuse to run without a real key.
    if os.environ.get('UCM_REQUIRE_DB_ENCRYPTION_KEY', '').lower() == 'true':
        raise RuntimeError(
            'UCM_DB_ENCRYPTION_KEY is not set and UCM_REQUIRE_DB_ENCRYPTION_KEY=true. '
            'Set UCM_DB_ENCRYPTION_KEY to a base64-encoded 32-byte Fernet key.'
        )

    logger.warning(
        'UCM_DB_ENCRYPTION_KEY is not set — falling back to a key derived from '
        'the machine id with a static, in-source salt. Anyone with a copy of '
        'the database and /etc/machine-id can decrypt all stored integration '
        'secrets. Set UCM_DB_ENCRYPTION_KEY (and UCM_REQUIRE_DB_ENCRYPTION_KEY=true '
        'to enforce it).'
    )

    # Generate deterministic key from machine-specific data
    # This ensures the same key is used across restarts
    machine_id_paths = [
        '/etc/machine-id',
        '/var/lib/dbus/machine-id',
        '/opt/ucm/data/.machine-key'
    ]
    
    machine_id = None
    for path in machine_id_paths:
        try:
            with open(path, 'r') as f:
                machine_id = f.read().strip()
                break
        except Exception:
            continue
    
    if not machine_id:
        # Create a persistent machine key
        import secrets
        machine_id = secrets.token_hex(32)
        try:
            os.makedirs('/opt/ucm/data', exist_ok=True)
            with open('/opt/ucm/data/.machine-key', 'w') as f:
                f.write(machine_id)
        except Exception:
            pass
    
    # Derive Fernet-compatible key (32 bytes, base64 encoded)
    derived = hashlib.pbkdf2_hmac(
        'sha256',
        machine_id.encode(),
        b'ucm-encryption-salt',
        100000,
        dklen=32
    )
    return base64.urlsafe_b64encode(derived)


@lru_cache(maxsize=1)
def get_cipher() -> Fernet:
    """Get cached Fernet cipher instance"""
    return Fernet(_get_encryption_key())


def encrypt_value(value: str) -> str:
    """
    Encrypt a string value for database storage.
    Returns base64-encoded encrypted string.
    """
    if not value:
        return value
    
    cipher = get_cipher()
    encrypted = cipher.encrypt(value.encode())
    return encrypted.decode()


def decrypt_value(encrypted: str) -> str:
    """
    Decrypt a value from database.
    Returns original string or None if decryption fails.
    """
    if not encrypted:
        return encrypted
    
    try:
        cipher = get_cipher()
        decrypted = cipher.decrypt(encrypted.encode())
        return decrypted.decode()
    except Exception:
        # Return None if decryption fails (corrupted or wrong key)
        return None


def is_encrypted(value: str) -> bool:
    """Check if a value appears to be encrypted (Fernet format)"""
    if not value:
        return False
    
    try:
        # Fernet tokens start with 'gAAAAA'
        return value.startswith('gAAAAA') and len(value) > 50
    except Exception:
        return False


def encrypt_if_needed(value: str) -> str:
    """Encrypt value only if not already encrypted"""
    if not value or is_encrypted(value):
        return value
    return encrypt_value(value)


def decrypt_if_needed(value: str) -> str:
    """Decrypt value only if it appears encrypted"""
    if not value or not is_encrypted(value):
        return value
    return decrypt_value(value)
