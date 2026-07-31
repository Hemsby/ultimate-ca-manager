"""Regression tests: CSR EKU pass-through cap (security audit v2.203, item #3).

For a leaf, whatever EKU the CSR carried was copied onto the certificate minus
only OCSPSigning/timeStamping. ``codeSigning``, ``emailProtection``,
``anyExtendedKeyUsage``, Microsoft Smartcard Logon and arbitrary custom OIDs all
passed through, and ``cert_type`` only ever *added* an EKU when the CSR omitted
one — it never constrained a CSR-supplied EKU. Combined with the ACME SAN issue
(#1), an ACME enrollee that proved only domain control could mint a code-signing
certificate.

The fix caps CSR-supplied EKUs to what the resolved certificate type permits.
The admin Sign-CSR path (allow_sensitive_ekus=True) is explicit operator intent
and keeps its historical behaviour; every protocol path is capped.
"""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from services.trust_store.trust_store_service import TrustStoreService

CODE_SIGNING = ExtendedKeyUsageOID.CODE_SIGNING
EMAIL_PROTECTION = ExtendedKeyUsageOID.EMAIL_PROTECTION
SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
ANY_EKU = x509.ObjectIdentifier('2.5.29.37.0')
SMARTCARD_LOGON = x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.2')


@pytest.fixture(scope='module')
def ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'EKU Cap CA')])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


@pytest.fixture(scope='module')
def leaf_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _csr(leaf_key, ekus):
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'leaf.example.com')])
    )
    if ekus:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(ekus), critical=False
        )
    return builder.sign(leaf_key, hashes.SHA256())


def _sign_and_get_ekus(ca, csr, **kwargs):
    ca_cert, ca_key = ca
    pem = TrustStoreService.sign_csr(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM),
        ca_cert=ca_cert,
        ca_private_key=ca_key,
        validity_days=30,
        **kwargs,
    )
    cert = x509.load_pem_x509_certificate(pem)
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
    except x509.ExtensionNotFound:
        return set()
    return set(ext.value)


# --- the vulnerability: protocol paths must not widen their own EKU ---------

def test_code_signing_stripped_from_server_cert(ca, leaf_key):
    """The ACME path signs with cert_type='server_cert'."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, CODE_SIGNING]),
        cert_type='server_cert',
    )
    assert CODE_SIGNING not in ekus
    assert SERVER_AUTH in ekus


def test_email_protection_stripped_from_server_cert(ca, leaf_key):
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, EMAIL_PROTECTION]),
        cert_type='server_cert',
    )
    assert EMAIL_PROTECTION not in ekus


def test_any_eku_stripped_from_server_cert(ca, leaf_key):
    """anyExtendedKeyUsage would make every EKU policy meaningless."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, ANY_EKU]), cert_type='server_cert',
    )
    assert ANY_EKU not in ekus


def test_smartcard_logon_stripped_from_server_cert(ca, leaf_key):
    """Smartcard logon + a UPN SAN is the AD-logon vector."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, SMARTCARD_LOGON]),
        cert_type='server_cert',
    )
    assert SMARTCARD_LOGON not in ekus


def test_custom_oid_stripped_from_server_cert(ca, leaf_key):
    custom = x509.ObjectIdentifier('1.3.6.1.4.1.99999.1.1')
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, custom]), cert_type='server_cert',
    )
    assert custom not in ekus


def test_code_signing_stripped_from_client_cert(ca, leaf_key):
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [CLIENT_AUTH, CODE_SIGNING]),
        cert_type='usr_cert',
    )
    assert CODE_SIGNING not in ekus
    assert CLIENT_AUTH in ekus


# --- legitimate uses keep working ------------------------------------------

def test_tls_pair_survives_on_server_cert(ca, leaf_key):
    """serverAuth+clientAuth is a normal mTLS-capable service certificate."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, CLIENT_AUTH]),
        cert_type='server_cert',
    )
    assert ekus == {SERVER_AUTH, CLIENT_AUTH}


def test_code_signing_kept_when_cert_type_is_code_signing(ca, leaf_key):
    """The resolved type — not the CSR — decides; asking properly works."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [CODE_SIGNING]), cert_type='code_signing',
    )
    assert CODE_SIGNING in ekus


def test_email_protection_kept_when_cert_type_is_email(ca, leaf_key):
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [EMAIL_PROTECTION]), cert_type='email_cert',
    )
    assert EMAIL_PROTECTION in ekus


def test_admin_sensitive_path_is_uncapped(ca, leaf_key):
    """allow_sensitive_ekus = deliberate operator action; behaviour unchanged."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, CODE_SIGNING]),
        cert_type='server_cert', allow_sensitive_ekus=True,
    )
    assert CODE_SIGNING in ekus


def test_operator_supplied_extra_ekus_are_not_capped(ca, leaf_key):
    """extra_ekus is explicit admin intent and merges in regardless."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH]),
        cert_type='server_cert',
        extra_ekus=[CODE_SIGNING.dotted_string],
    )
    assert CODE_SIGNING in ekus


def test_extra_eku_remerge_does_not_resurrect_capped_eku(ca, leaf_key):
    """The extra_ekus re-merge path must apply the same cap to CSR EKUs.

    Regression guard: the re-merge branch rebuilds the EKU extension from the
    CSR's original list, so it must filter too, or requesting any extra EKU
    would restore the ones the copy loop just dropped.
    """
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, CODE_SIGNING]),
        cert_type='server_cert',
        extra_ekus=[CLIENT_AUTH.dotted_string],
    )
    assert CODE_SIGNING not in ekus
    assert CLIENT_AUTH in ekus


# --- total drop must not yield an UNRESTRICTED certificate ------------------
#
# Every test above pairs the forbidden EKU with a surviving one, so the cap
# always had something left to emit. When the cap refused EVERY requested EKU
# the ExtendedKeyUsage extension was omitted entirely — and a leaf with no EKU
# extension is unrestricted for all purposes (RFC 5280 §4.2.1.12): a CSR
# requesting nothing got serverAuth, while a CSR requesting something
# forbidden got everything. The filter now falls back to the certificate
# type's own profile, and refuses outright when the type has none.

def test_all_ekus_dropped_falls_back_to_type_profile(ca, leaf_key):
    """A CSR whose every EKU is refused must not yield an EKU-less leaf."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [CODE_SIGNING]), cert_type='server_cert',
    )
    assert ekus, 'certificate has no EKU extension: unrestricted'
    assert ekus == {SERVER_AUTH}


def test_all_ekus_dropped_falls_back_for_client_cert(ca, leaf_key):
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [CODE_SIGNING]), cert_type='usr_cert',
    )
    assert ekus == {CLIENT_AUTH}


def test_any_eku_alone_does_not_yield_unrestricted_leaf(ca, leaf_key):
    """anyEKU alone was the cheapest route to an unrestricted certificate."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [ANY_EKU]), cert_type='server_cert',
    )
    assert ekus == {SERVER_AUTH}


def test_all_ekus_dropped_on_unprofiled_type_is_refused(ca, leaf_key):
    """A type with no profile has nothing to fall back to: refuse outright."""
    with pytest.raises(ValueError, match='not permitted'):
        _sign_and_get_ekus(
            ca, _csr(leaf_key, [ANY_EKU]), cert_type='custom',
        )


def test_no_eku_csr_gets_the_code_signing_profile(ca, leaf_key):
    """Requesting nothing and requesting only-forbidden resolve identically.

    The no-EKU default and the total-drop fallback share one profile map, so
    typed certificates (code_signing here) no longer issue EKU-less —
    unrestricted — when the CSR simply omits the extension.
    """
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, None), cert_type='code_signing',
    )
    assert ekus == {CODE_SIGNING}


def test_every_ceiling_type_has_a_default_within_the_ceiling():
    """Two invariants the signing paths rely on, pinned per type.

    default ⊆ ceiling: a type's silent default grants its core purpose; its
    ceiling is what a CSR may explicitly request on top (server_cert defaults
    to serverAuth but permits clientAuth; email_cert defaults to
    emailProtection but permits clientAuth for S/MIME + TLS-client devices).
    The ceiling being wider than the default is deliberate — the default must
    never exceed the ceiling, or a no-EKU CSR would receive more than any
    explicit CSR may request.

    default non-empty: the total-drop fallback issues the default profile,
    and refuses outright only for types with no ceiling entry. A ceiling type
    with an empty default would turn an all-refused CSR into a hard failure
    instead of the profile.
    """
    from services.trust_store.csr_operations_mixin import (
        _CERT_TYPE_ALLOWED_EKUS,
        _default_ekus_for_cert_type,
    )
    for cert_type, allowed in _CERT_TYPE_ALLOWED_EKUS.items():
        default = _default_ekus_for_cert_type(cert_type)
        assert default, (
            f'{cert_type!r} has an EKU ceiling but no default profile: an '
            'all-refused CSR would raise instead of falling back'
        )
        assert set(default) <= set(allowed), (
            f'{cert_type!r} default {sorted(o.dotted_string for o in default)} '
            'exceeds its own ceiling'
        )
