"""Interoperability tests for the MS-WSTEP UsernamePassword-bound issue endpoint."""
import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from lxml import etree

from models import CA, db
from models.system_config import SystemConfig
from services.wstep.soap_envelope import ADDRESSING_NS, SOAP_NS, WSSE_NS, WST_NS


ISSUE_URL = '/ADCertificateService_CES_UsernamePassword/service.svc'
WSTEP_USER = 'wstep-test'
WSTEP_PASSWORD = 'wstep-password'


def _set_config(key, value):
    row = SystemConfig.query.filter_by(key=key).first()
    if row is None:
        db.session.add(SystemConfig(key=key, value=value))
    else:
        row.value = value
    db.session.commit()


@pytest.fixture(scope='module')
def wstep_config(app, create_ca):
    ca_data = create_ca(cn='WSTEP Issue CA')
    keys = ('wstep_enabled', 'wstep_ca_refid', 'wstep_username', 'wstep_password', 'wstep_validity_days')
    with app.app_context():
        previous = {
            key: (SystemConfig.query.filter_by(key=key).first().value
                  if SystemConfig.query.filter_by(key=key).first() else None)
            for key in keys
        }
        ca = db.session.get(CA, ca_data['id'])
        _set_config('wstep_enabled', 'true')
        _set_config('wstep_ca_refid', ca.refid)
        _set_config('wstep_username', WSTEP_USER)
        _set_config('wstep_password', WSTEP_PASSWORD)
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


def _basic_auth():
    token = base64.b64encode(f'{WSTEP_USER}:{WSTEP_PASSWORD}'.encode()).decode()
    return {'Authorization': f'Basic {token}'}


def _make_csr(common_name='device.example.test', key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    ).sign(key, hashes.SHA256())
    return csr, key


def _build_rst(csr, message_id='urn:uuid:test-rst-1'):
    NSMAP = {'s': SOAP_NS, 'a': ADDRESSING_NS, 'wst': WST_NS, 'wsse': WSSE_NS}
    envelope = etree.Element('{%s}Envelope' % SOAP_NS, nsmap=NSMAP)
    header = etree.SubElement(envelope, '{%s}Header' % SOAP_NS)
    etree.SubElement(header, '{%s}MessageID' % ADDRESSING_NS).text = message_id
    body = etree.SubElement(envelope, '{%s}Body' % SOAP_NS)
    rst = etree.SubElement(body, '{%s}RequestSecurityToken' % WST_NS)
    etree.SubElement(rst, '{%s}TokenType' % WST_NS).text = (
        'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
    )
    etree.SubElement(rst, '{%s}RequestType' % WST_NS).text = (
        'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
    )
    bst = etree.SubElement(
        rst, '{%s}BinarySecurityToken' % WSSE_NS,
        ValueType='http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10',
        EncodingType='base64',
    )
    bst.text = base64.b64encode(csr.public_bytes(Encoding.DER)).decode()
    return etree.tostring(envelope, xml_declaration=True, encoding='UTF-8')


def _build_rst_with_username_token(csr, username, password, message_id='urn:uuid:test-rst-token'):
    """Real client behavior: credentials in a WS-Security UsernameToken
    inside the RST's ``wsse:Security`` header, not an HTTP Authorization
    header — see MS-XCEP's published GetPolicies example, which uses the
    same mechanism for this auth binding."""
    NSMAP = {'s': SOAP_NS, 'a': ADDRESSING_NS, 'wst': WST_NS, 'wsse': WSSE_NS}
    envelope = etree.Element('{%s}Envelope' % SOAP_NS, nsmap=NSMAP)
    header = etree.SubElement(envelope, '{%s}Header' % SOAP_NS)
    etree.SubElement(header, '{%s}MessageID' % ADDRESSING_NS).text = message_id
    security = etree.SubElement(header, '{%s}Security' % WSSE_NS)
    token = etree.SubElement(security, '{%s}UsernameToken' % WSSE_NS)
    etree.SubElement(token, '{%s}Username' % WSSE_NS).text = username
    etree.SubElement(token, '{%s}Password' % WSSE_NS).text = password
    body = etree.SubElement(envelope, '{%s}Body' % SOAP_NS)
    rst = etree.SubElement(body, '{%s}RequestSecurityToken' % WST_NS)
    bst = etree.SubElement(
        rst, '{%s}BinarySecurityToken' % WSSE_NS,
        ValueType='http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10',
        EncodingType='base64',
    )
    bst.text = base64.b64encode(csr.public_bytes(Encoding.DER)).decode()
    return etree.tostring(envelope, xml_declaration=True, encoding='UTF-8')


def _issued_cert_from_rstr(response_bytes):
    root = etree.fromstring(response_bytes)
    bst_el = root.find(f'.//{{{WSSE_NS}}}BinarySecurityToken')
    assert bst_el is not None and bst_el.text
    return x509.load_der_x509_certificate(base64.b64decode(bst_el.text))


def test_issue_disabled_returns_503(client, app):
    with app.app_context():
        row = SystemConfig.query.filter_by(key='wstep_enabled').first()
        previous = row.value if row else None
        _set_config('wstep_enabled', 'false')
    try:
        csr, _key = _make_csr()
        r = client.post(ISSUE_URL, data=_build_rst(csr), headers=_basic_auth())
        assert r.status_code == 503
    finally:
        with app.app_context():
            if previous is None:
                SystemConfig.query.filter_by(key='wstep_enabled').delete()
                db.session.commit()
            else:
                _set_config('wstep_enabled', previous)


def test_issue_requires_authentication(client, wstep_config):
    """Auth failure is a SOAP fault, not an HTTP 401/WWW-Authenticate
    challenge — real credentials arrive as a WS-Security UsernameToken
    inside the RST body, and a client configured for that binding refuses
    to respond to a Basic challenge at all (WS_E_SERVER_REQUIRES_BASIC_AUTH),
    so this endpoint never issues one."""
    csr, _key = _make_csr()
    r = client.post(ISSUE_URL, data=_build_rst(csr))
    assert r.status_code == 400
    assert 'WWW-Authenticate' not in r.headers


def test_issue_rejects_bad_credentials(client, wstep_config):
    token = base64.b64encode(b'wstep-test:wrong-password').decode()
    csr, _key = _make_csr()
    r = client.post(
        ISSUE_URL, data=_build_rst(csr),
        headers={'Authorization': f'Basic {token}'},
    )
    assert r.status_code == 400
    assert 'WWW-Authenticate' not in r.headers


def test_issue_returns_certificate(client, wstep_config):
    csr, _key = _make_csr(common_name='wstep-issue.example.test')
    r = client.post(ISSUE_URL, data=_build_rst(csr, message_id='urn:uuid:happy-path'), headers=_basic_auth())
    assert r.status_code == 200
    assert r.content_type.startswith('application/soap+xml')

    root = etree.fromstring(r.data)
    relates_to = root.find(f'.//{{{ADDRESSING_NS}}}RelatesTo')
    assert relates_to is not None and relates_to.text == 'urn:uuid:happy-path'

    cert = _issued_cert_from_rstr(r.data)
    assert cert.subject.rfc4514_string() == 'CN=wstep-issue.example.test'


def test_issue_authenticates_via_username_token(client, wstep_config):
    """Regression test for the bug where this endpoint only accepted HTTP
    Basic, causing a real Windows client (configured for message-level
    auth) to report WS_E_SERVER_REQUIRES_BASIC_AUTH and refuse to enroll."""
    csr, _key = _make_csr(common_name='wstep-token-auth.example.test')
    r = client.post(
        ISSUE_URL,
        data=_build_rst_with_username_token(csr, WSTEP_USER, WSTEP_PASSWORD),
    )
    assert r.status_code == 200
    cert = _issued_cert_from_rstr(r.data)
    assert cert.subject.rfc4514_string() == 'CN=wstep-token-auth.example.test'


def test_issue_rejects_invalid_csr_pop(client, wstep_config):
    """A CSR whose self-signature doesn't verify must be refused (proof
    of possession), mirroring EST's ``_validate_est_csr``."""
    csr, _key = _make_csr()
    csr_der = bytearray(csr.public_bytes(Encoding.DER))
    csr_der[-1] ^= 0xFF  # corrupt the trailing signature byte
    envelope = etree.fromstring(_build_rst(csr))
    bst_el = envelope.find(f'.//{{{WSSE_NS}}}BinarySecurityToken')
    bst_el.text = base64.b64encode(bytes(csr_der)).decode()
    tampered = etree.tostring(envelope, xml_declaration=True, encoding='UTF-8')

    r = client.post(ISSUE_URL, data=tampered, headers=_basic_auth())
    assert r.status_code == 400


def test_issue_rejects_empty_cn(client, wstep_config):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
    r = client.post(ISSUE_URL, data=_build_rst(csr), headers=_basic_auth())
    assert r.status_code == 400
