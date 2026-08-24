"""Public-key correspondence checks (DER SubjectPublicKeyInfo comparison).

Shared by flows that must prove a certificate (or CSR) belongs to a stored
private key — notably the external-CSR CA completion (#298), where the
uploaded certificate is only accepted if its public key matches the key UCM
generated. Works with HSM-backed keys: the HSM wrappers expose public_key()
like any cryptography private key.
"""
from cryptography.hazmat.primitives import serialization


def public_keys_equal(key1, key2) -> bool:
    """Compare two public keys by DER-encoded SubjectPublicKeyInfo."""
    try:
        der1 = key1.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        der2 = key2.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return der1 == der2
    except Exception:
        return False


def certificate_matches_private_key(cert, private_key) -> bool:
    """True iff the certificate's public key matches the private key's."""
    try:
        return public_keys_equal(cert.public_key(), private_key.public_key())
    except Exception:
        return False
