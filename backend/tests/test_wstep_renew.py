"""Interoperability tests for the MS-WSTEP Certificate-bound renewal endpoint."""
import base64
import datetime

import pytest
import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from models import CA, Certificate, db
from models.system_config import SystemConfig
from services.ca_service import CAService
from services.wstep.soap_envelope import ADDRESSING_NS, SOAP_NS, WSSE_NS, WST_NS, WSU_NS


RENEW_URL = '/ADCertificateService_CES_Certificate/service.svc'


def _set_config(key, value):
    row = SystemConfig.query.filter_by(key=key).first()
    if row is None:
        db.session.add(SystemConfig(key=key, value=value))
    else:
        row.value = value
    db.session.commit()


@pytest.fixture(scope='module')
def wstep_renew_config(app, create_ca):
    ca_data = create_ca(cn='WSTEP Renewal CA')
    keys = ('wstep_enabled', 'wstep_ca_refid', 'wstep_validity_days')
    with app.app_context():
        previous = {
            key: (SystemConfig.query.filter_by(key=key).first().value
                  if SystemConfig.query.filter_by(key=key).first() else None)
            for key in keys
        }
        ca = db.session.get(CA, ca_data['id'])
        _set_config('wstep_enabled', 'true')
        _set_config('wstep_ca_refid', ca.refid)
        _set_config('wstep_validity_days', '30')

    yield ca_data

    with app.app_context():
        for key, value in previous.items():
            row = SystemConfig.query.filter_by(key=key).first()
            if value is None:
                if row is not None:
                    db.session.delete(row)
            elif row is None:
                db.session.add(SystemConfig(key=key, value=value))
            else:
                row.value = value
        db.session.commit()


def _issue_test_cert(app, ca_data, common_name='wstep-renew.example.test'):
    """Issue a real cert through CAService (not the HTTP endpoint) so
    each test gets its own already-issued cert/key pair to renew from."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    ).sign(key, hashes.SHA256())
    with app.app_context():
        ca = db.session.get(CA, ca_data['id'])
        cert_pem, _serial = CAService.sign_csr_from_crypto(
            ca=ca, csr=csr, validity_days=30, source='test',
        )
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return cert, key


def _build_signed_rst(signing_cert, signing_key, csr, message_id='urn:uuid:renew-1', corrupt_signature=False):
    NSMAP = {'s': SOAP_NS, 'a': ADDRESSING_NS, 'wst': WST_NS, 'wsse': WSSE_NS, 'wsu': WSU_NS}
    envelope = etree.Element('{%s}Envelope' % SOAP_NS, nsmap=NSMAP)
    header = etree.SubElement(envelope, '{%s}Header' % SOAP_NS)
    etree.SubElement(header, '{%s}MessageID' % ADDRESSING_NS).text = message_id
    security = etree.SubElement(header, '{%s}Security' % WSSE_NS)
    sec_bst = etree.SubElement(
        security, '{%s}BinarySecurityToken' % WSSE_NS,
        ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3',
        EncodingType='base64',
    )
    sec_bst.text = base64.b64encode(
        signing_cert.public_bytes(serialization.Encoding.DER)
    ).decode()

    body = etree.SubElement(envelope, '{%s}Body' % SOAP_NS)
    body.set('{%s}Id' % WSU_NS, 'body-1')
    rst = etree.SubElement(body, '{%s}RequestSecurityToken' % WST_NS)
    etree.SubElement(rst, '{%s}TokenType' % WST_NS).text = (
        'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
    )
    bst = etree.SubElement(
        rst, '{%s}BinarySecurityToken' % WSSE_NS,
        ValueType='http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10',
        EncodingType='base64',
    )
    bst.text = base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()

    sig_node = xmlsec.template.create(
        security, xmlsec.constants.TransformExclC14N, xmlsec.constants.TransformRsaSha256
    )
    security.append(sig_node)
    ref = xmlsec.template.add_reference(sig_node, xmlsec.constants.TransformSha256, uri='#body-1')
    xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)

    ctx = xmlsec.SignatureContext()
    ctx.register_id(body, id_attr='Id', id_ns=WSU_NS)
    key_pem = signing_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    ctx.key = xmlsec.Key.from_memory(key_pem, xmlsec.constants.KeyDataFormatPem)
    ctx.sign(sig_node)

    xml_bytes = etree.tostring(envelope, xml_declaration=True, encoding='UTF-8')
    if corrupt_signature:
        csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.DER))
        xml_bytes = xml_bytes.replace(csr_b64, csr_b64[:-4] + b'XXXX')
    return xml_bytes


def _renewal_csr(subject, key):
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())


def test_renew_disabled_returns_503(client, app):
    with app.app_context():
        row = SystemConfig.query.filter_by(key='wstep_enabled').first()
        previous = row.value if row else None
        _set_config('wstep_enabled', 'false')
    try:
        r = client.post(RENEW_URL, data=b'<GetPolicies/>')
        assert r.status_code == 503
    finally:
        with app.app_context():
            if previous is None:
                SystemConfig.query.filter_by(key='wstep_enabled').delete()
                db.session.commit()
            else:
                _set_config('wstep_enabled', previous)


def test_renew_requires_signature(client, app, wstep_renew_config):
    cert, key = _issue_test_cert(app, wstep_renew_config)
    csr = _renewal_csr(cert.subject, key)
    # Build an RST with no wsse:Security header at all.
    NSMAP = {'s': SOAP_NS, 'a': ADDRESSING_NS, 'wst': WST_NS, 'wsse': WSSE_NS}
    envelope = etree.Element('{%s}Envelope' % SOAP_NS, nsmap=NSMAP)
    body = etree.SubElement(envelope, '{%s}Body' % SOAP_NS)
    rst = etree.SubElement(body, '{%s}RequestSecurityToken' % WST_NS)
    bst = etree.SubElement(rst, '{%s}BinarySecurityToken' % WSSE_NS, EncodingType='base64')
    bst.text = base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()
    unsigned = etree.tostring(envelope, xml_declaration=True, encoding='UTF-8')

    r = client.post(RENEW_URL, data=unsigned)
    assert r.status_code == 400


def test_renew_rejects_tampered_signature(client, app, wstep_renew_config):
    cert, key = _issue_test_cert(app, wstep_renew_config)
    csr = _renewal_csr(cert.subject, key)
    tampered = _build_signed_rst(cert, key, csr, corrupt_signature=True)
    r = client.post(RENEW_URL, data=tampered)
    assert r.status_code == 400


def test_renew_rejects_unrecognized_certificate(client, app, wstep_renew_config):
    """A certificate UCM never issued (self-signed, matching key pair,
    valid signature) must still be refused — cryptographic validity of
    the signature is not the same as trust."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'unknown-client.example.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    foreign_cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    csr = _renewal_csr(name, key)
    signed = _build_signed_rst(foreign_cert, key, csr)
    r = client.post(RENEW_URL, data=signed)
    assert r.status_code == 400


def test_renew_rejects_subject_mismatch(client, app, wstep_renew_config):
    cert, key = _issue_test_cert(app, wstep_renew_config, common_name='subject-match.example.test')
    mismatched_csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'someone-else.example.test')])
    ).sign(key, hashes.SHA256())
    signed = _build_signed_rst(cert, key, mismatched_csr)
    r = client.post(RENEW_URL, data=signed)
    assert r.status_code == 400


def test_renew_succeeds_and_reissues(client, app, wstep_renew_config):
    cert, key = _issue_test_cert(app, wstep_renew_config, common_name='renew-happy-path.example.test')
    csr = _renewal_csr(cert.subject, key)
    signed = _build_signed_rst(cert, key, csr, message_id='urn:uuid:renew-happy')

    r = client.post(RENEW_URL, data=signed)
    assert r.status_code == 200
    assert r.content_type.startswith('application/soap+xml')

    root = etree.fromstring(r.data)
    relates_to = root.find(f'.//{{{ADDRESSING_NS}}}RelatesTo')
    assert relates_to is not None and relates_to.text == 'urn:uuid:renew-happy'

    bst_el = root.find(f'.//{{{WSSE_NS}}}BinarySecurityToken')
    new_cert = x509.load_der_x509_certificate(base64.b64decode(bst_el.text))
    assert new_cert.subject == cert.subject
    assert new_cert.serial_number != cert.serial_number

    with app.app_context():
        db_row = Certificate.query.filter_by(serial_number=str(new_cert.serial_number)).first()
        assert db_row is not None
