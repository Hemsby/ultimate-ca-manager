"""Regression test: issue #271 (empty-subject CSR with an IP-only SAN).

``TrustStoreService.sign_csr`` already fills the CN from the CSR's first SAN
when the subject is empty, but it only checked ``x509.DNSName`` entries, never
``x509.IPAddress``. certbot 2.x sends subject-less CSRs by default; a reporter
hit this with a single IP-typed SAN (``IP Address:10.10.5.54``), so the
fallback silently didn't fire and the issued certificate carried a genuinely
empty Subject. This path is shared by every issuance route (ACME, admin
sign-CSR, EST/SCEP, WSTEP), so the fix extends the existing DNSName branch to
also handle IPAddress, stringifying the address into the CN.
"""
import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from services.trust_store.trust_store_service import TrustStoreService


def _ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Issue 271 CA')])
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


def _csr_no_subject(san_entries):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_entries), critical=False
    )
    return builder.sign(key, hashes.SHA256())


def _sign(ca, csr):
    ca_cert, ca_key = ca
    pem = TrustStoreService.sign_csr(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM),
        ca_cert=ca_cert,
        ca_private_key=ca_key,
        validity_days=30,
    )
    return x509.load_pem_x509_certificate(pem)


def test_empty_subject_ip_only_san_populates_cn_from_ip():
    """The exact issue #271 shape: no subject, single IP-typed SAN."""
    csr = _csr_no_subject([x509.IPAddress(ipaddress.ip_address('10.10.5.54'))])
    cert = _sign(_ca(), csr)
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cns) == 1
    assert cns[0].value == '10.10.5.54'


def test_empty_subject_dns_san_still_populates_cn_from_dns():
    """Existing DNSName fallback must keep working alongside the new branch."""
    csr = _csr_no_subject([x509.DNSName('web.example.com')])
    cert = _sign(_ca(), csr)
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cns) == 1
    assert cns[0].value == 'web.example.com'


def test_empty_subject_ip_first_san_wins_over_later_dns():
    """The fallback takes the *first* SAN entry, matching the DNSName behaviour."""
    csr = _csr_no_subject([
        x509.IPAddress(ipaddress.ip_address('10.10.5.54')),
        x509.DNSName('web.example.com'),
    ])
    cert = _sign(_ca(), csr)
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cns) == 1
    assert cns[0].value == '10.10.5.54'
