"""Unit tests for TrustStoreService.sign_csr's ``override_subject`` parameter
(used by WSTEP's Kerberos binding to derive a subject for the "naked" CSRs
real Windows GPO machine autoenrollment submits -- see wstep_service.py and
services/ad_connector/lookup.py).

The critical regression case: ``override_subject`` must be validated
against the CA's NameConstraints exactly like the CSR's own subject would
be -- applying it *after* that check would let a CA's NameConstraints be
silently bypassed by whatever subject was derived server-side.
"""
import pytest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from services.trust_store.trust_store_service import TrustStoreService


def _test_ca(name_constraints=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Override Subject Test CA')])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    cert = builder.sign(key, hashes.SHA256())
    return cert, key


def _naked_csr():
    """No CN, no SAN -- what real Windows GPO machine autoenrollment
    submits for machine templates."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([])
    ).sign(key, hashes.SHA256())


def _sign(csr, ca_cert, ca_key, **kwargs):
    pem = TrustStoreService.sign_csr(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM),
        ca_cert=ca_cert,
        ca_private_key=ca_key,
        validity_days=30,
        **kwargs,
    )
    return x509.load_pem_x509_certificate(pem, default_backend())


def _san_dns_names(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


class TestOverrideSubject:
    def test_naked_csr_gets_override_subject_and_synthesized_san(self, app):
        ca_cert, ca_key = _test_ca()
        csr = _naked_csr()
        override = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'win11.hagland.domain')])
        with app.app_context():
            cert = _sign(csr, ca_cert, ca_key, override_subject=override)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'win11.hagland.domain'
        assert _san_dns_names(cert) == ['win11.hagland.domain']

    def test_override_subject_honors_name_constraints(self, app):
        """The regression test: a naked CSR overridden with a name OUTSIDE
        the CA's permitted NameConstraints subtree must be rejected, not
        silently issued -- proves the override is validated before the
        certificate is built, not after."""
        constraints = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName('corp.example')],
            excluded_subtrees=None,
        )
        ca_cert, ca_key = _test_ca(name_constraints=constraints)
        csr = _naked_csr()
        disallowed = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'win11.hagland.domain')])
        with app.app_context():
            with pytest.raises(ValueError):
                _sign(csr, ca_cert, ca_key, override_subject=disallowed)

    def test_override_subject_within_name_constraints_succeeds(self, app):
        constraints = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName('hagland.domain')],
            excluded_subtrees=None,
        )
        ca_cert, ca_key = _test_ca(name_constraints=constraints)
        csr = _naked_csr()
        allowed = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'win11.hagland.domain')])
        with app.app_context():
            cert = _sign(csr, ca_cert, ca_key, override_subject=allowed)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'win11.hagland.domain'

    def test_no_override_leaves_existing_behavior_unchanged(self, app):
        """A CSR with a real subject and no override must be completely
        unaffected -- regression guard for every non-WSTEP-Kerberos caller."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'normal.example.com')])
        ).sign(key, hashes.SHA256())
        ca_cert, ca_key = _test_ca()
        with app.app_context():
            cert = _sign(csr, ca_cert, ca_key)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'normal.example.com'
