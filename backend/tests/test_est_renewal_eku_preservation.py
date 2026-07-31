"""Regression tests: EST/auto-renewal EKU preservation (audit follow-up to
the v2.203 EKU cap, item #3).

The per-type EKU ceiling landed with EST and auto-renewal calling the signing
service without a ``cert_type``, so both defaulted to ``server_cert`` whose
allowed set is {serverAuth, clientAuth}: a device whose current certificate
legitimately carries ipsecIKE, emailProtection or codeSigning lost it on
renewal — the client gets a 200 and a valid PKCS#7, the drop is only a
server-side warning, and the service breaks downstream with no error
anywhere. SCEP already implements exactly this preservation
(``scep_service._ALLOWED_EKU_OIDS`` + renewal-at-par), so the equivalent
protocol had a wider, reviewed ceiling than EST.

Two-part fix, mirrored here:
- renewal at par: ``renewal_of`` widens the ceiling by the EKUs the
  certificate being renewed already carries (the hard block-list —
  OCSPSigning/timeStamping/anyEKU/Smartcard Logon — is never resurrected);
- EST signs under a ``device_cert`` profile matching SCEP's allow-list, and
  the AST tests below pin that wiring so a new EST call site cannot silently
  fall back to the TLS-server profile again.
"""
import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from services.trust_store.trust_store_service import TrustStoreService

SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
IPSEC_IKE = ExtendedKeyUsageOID.IPSEC_IKE
EMAIL_PROTECTION = ExtendedKeyUsageOID.EMAIL_PROTECTION
CODE_SIGNING = ExtendedKeyUsageOID.CODE_SIGNING
OCSP_SIGNING = ExtendedKeyUsageOID.OCSP_SIGNING
ANY_EKU = x509.ObjectIdentifier('2.5.29.37.0')
SMARTCARD_LOGON = x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.2')

_BACKEND = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Renewal CA')])
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
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device.example.com')])
    )
    if ekus:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(ekus), critical=False
        )
    return builder.sign(leaf_key, hashes.SHA256())


def _prior_cert(leaf_key, ekus):
    """The device's current certificate, as auto-renewal/EST reenroll load it."""
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'device.example.com')]
    )
    return (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=300))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=65))
            .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
            .sign(leaf_key, hashes.SHA256()))


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


# --- renewal at par ---------------------------------------------------------

def test_renewal_preserves_prior_ipsec_ike(ca, leaf_key):
    """Auto-renewal signs with the default cert_type: the EKUs the current
    certificate already carries must survive, or a VPN device renews into a
    certificate that can no longer do IKE — with no error anywhere."""
    prior = _prior_cert(leaf_key, [IPSEC_IKE, SERVER_AUTH])
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [IPSEC_IKE, SERVER_AUTH]), renewal_of=prior,
    )
    assert IPSEC_IKE in ekus
    assert SERVER_AUTH in ekus


def test_renewal_preserves_prior_email_protection(ca, leaf_key):
    prior = _prior_cert(leaf_key, [EMAIL_PROTECTION, CLIENT_AUTH])
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [EMAIL_PROTECTION, CLIENT_AUTH]), renewal_of=prior,
    )
    assert EMAIL_PROTECTION in ekus


def test_renewal_is_at_par_not_a_widening(ca, leaf_key):
    """Only EKUs the prior certificate ACTUALLY carries are graced — a
    renewal CSR asking for more than the device has stays capped."""
    prior = _prior_cert(leaf_key, [SERVER_AUTH])
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, CODE_SIGNING]), renewal_of=prior,
    )
    assert CODE_SIGNING not in ekus
    assert SERVER_AUTH in ekus


def test_renewal_does_not_resurrect_ocsp_signing(ca, leaf_key):
    """The hard block-list wins over renewal-at-par: a delegated-responder
    EKU on the old certificate must not ride back in through a protocol
    renewal (the admin Sign-CSR path exists for that)."""
    prior = _prior_cert(leaf_key, [OCSP_SIGNING, SERVER_AUTH])
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [OCSP_SIGNING, SERVER_AUTH]), renewal_of=prior,
    )
    assert OCSP_SIGNING not in ekus
    assert SERVER_AUTH in ekus


def test_renewal_does_not_resurrect_any_eku_or_smartcard(ca, leaf_key):
    prior = _prior_cert(leaf_key, [ANY_EKU, SMARTCARD_LOGON, SERVER_AUTH])
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [ANY_EKU, SMARTCARD_LOGON, SERVER_AUTH]),
        renewal_of=prior,
    )
    assert ANY_EKU not in ekus
    assert SMARTCARD_LOGON not in ekus


# --- the EST device profile -------------------------------------------------

def test_device_profile_keeps_ipsec_ike_on_first_enrollment(ca, leaf_key):
    """First enrollment has no prior certificate to grace: the device profile
    itself must permit what SCEP's reviewed allow-list permits."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [IPSEC_IKE, SERVER_AUTH]), cert_type='device_cert',
    )
    assert ekus == {IPSEC_IKE, SERVER_AUTH}


def test_device_profile_still_strips_smartcard_logon(ca, leaf_key):
    """The wider device ceiling must not loosen the hard block-list."""
    ekus = _sign_and_get_ekus(
        ca, _csr(leaf_key, [SERVER_AUTH, SMARTCARD_LOGON, OCSP_SIGNING]),
        cert_type='device_cert',
    )
    assert SMARTCARD_LOGON not in ekus
    assert OCSP_SIGNING not in ekus
    assert SERVER_AUTH in ekus


def test_device_profile_no_eku_csr_gets_tls_pair(ca, leaf_key):
    """A no-EKU device CSR gets the combined TLS default, not an EKU-less
    (unrestricted) certificate."""
    ekus = _sign_and_get_ekus(ca, _csr(leaf_key, None), cert_type='device_cert')
    assert ekus == {SERVER_AUTH, CLIENT_AUTH}


# --- wiring: the profile is only real if the EST endpoints actually pass it -

def _calls_to(tree, func_name):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = (func.attr if isinstance(func, ast.Attribute)
                    else getattr(func, 'id', None))
            if name == func_name:
                yield node


def test_every_est_signing_call_pins_the_device_profile():
    """Pin the call sites, not a hardcoded count: any EST handler that calls
    the signing bridge without an explicit cert_type falls back to the
    server_cert profile and silently strips device EKUs again."""
    src = (_BACKEND / 'api' / 'est_protocol.py').read_text(encoding='utf-8')
    calls = list(_calls_to(ast.parse(src), 'sign_csr_from_crypto'))
    assert calls, 'est_protocol.py no longer calls sign_csr_from_crypto'
    for call in calls:
        keywords = {kw.arg: kw.value for kw in call.keywords}
        assert 'cert_type' in keywords, (
            f'est_protocol.py:{call.lineno}: sign_csr_from_crypto call '
            'without cert_type defaults to the server_cert EKU ceiling'
        )
        value = keywords['cert_type']
        assert isinstance(value, ast.Constant) and value.value == 'device_cert', (
            f'est_protocol.py:{call.lineno}: EST must sign under the '
            'device_cert profile'
        )


def test_signing_bridge_forwards_cert_type():
    """sign_csr_from_crypto must forward cert_type to TrustStoreService —
    accepting the parameter and dropping it would silently re-open the gap."""
    src = (_BACKEND / 'services' / 'ca' / 'ca_signing.py').read_text(
        encoding='utf-8'
    )
    calls = list(_calls_to(ast.parse(src), 'sign_csr'))
    assert calls, 'ca_signing.py no longer calls TrustStoreService.sign_csr'
    for call in calls:
        keyword_names = {kw.arg for kw in call.keywords}
        assert 'cert_type' in keyword_names, (
            f'ca_signing.py:{call.lineno}: sign_csr call does not forward '
            'cert_type'
        )
