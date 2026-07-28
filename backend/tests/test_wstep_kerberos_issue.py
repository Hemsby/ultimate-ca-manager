"""Interoperability tests for MS-WSTEP's Kerberos-bound CES endpoint (Phase 3).

Same constraint as test_xcep_kerberos_policy.py: no real KDC in a unit test
environment, so ``negotiate_auth.authenticate_negotiate`` is monkeypatched
for the "ticket already verified" path. Real end-to-end verification is a
lab AD exercise (see memory/project_xcep_wstep_lab_testing.md).
"""
import base64
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from lxml import etree

from models import CA, ADConnectorConfig, AuditLog, Certificate, db
from models.certificate_template import CertificateTemplate
from models.system_config import SystemConfig
from services.ad_connector import lookup as ad_lookup
from services.kerberos import negotiate_auth
from services.wstep.soap_envelope import ADDRESSING_NS, SOAP_NS, WST_NS, WSSE_NS
from utils.upn_san import extract_upns_from_san_list

ISSUE_URL = '/ADCertificateService_CES_Kerberos/service.svc'
KERBEROS_PRINCIPAL = 'HOST$@HAGLAND.DOMAIN'


def _set_config(key, value):
    row = SystemConfig.query.filter_by(key=key).first()
    if row is None:
        db.session.add(SystemConfig(key=key, value=value))
    else:
        row.value = value
    db.session.commit()


@pytest.fixture(scope='module')
def wstep_kerberos_config(app, create_ca):
    ca_data = create_ca(cn='WSTEP Kerberos CA')
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


def _make_csr(common_name='machine.hagland.domain'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    ).sign(key, hashes.SHA256())
    return csr, key


def _make_naked_csr():
    """No CN, no SAN -- what real Windows GPO machine autoenrollment
    submits, trusting the CA to derive the subject from AD."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([])
    ).sign(key, hashes.SHA256())
    return csr, key


def _build_rst(csr, message_id='urn:uuid:test-krb-rst-1'):
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


def _issued_cert_from_rstr(response_bytes):
    root = etree.fromstring(response_bytes)
    bst_el = root.find(f'.//{{{WSSE_NS}}}BinarySecurityToken')
    assert bst_el is not None and bst_el.text
    return x509.load_der_x509_certificate(base64.b64decode(bst_el.text))


def _authenticated_result(token_b64=None):
    return negotiate_auth.NegotiateResult(
        status='authenticated', client_principal=KERBEROS_PRINCIPAL, response_token_b64=token_b64,
    )


def test_issue_503_when_not_configured(client, wstep_kerberos_config, monkeypatch):
    monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
    monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: False)
    csr, _key = _make_csr()
    r = client.post(ISSUE_URL, data=_build_rst(csr), headers={'Authorization': 'Negotiate dG9rZW4='})
    assert r.status_code == 503


def test_issue_challenges_without_authorization_header(client, wstep_kerberos_config, monkeypatch):
    monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
    monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
    csr, _key = _make_csr()
    r = client.post(ISSUE_URL, data=_build_rst(csr))
    assert r.status_code == 401
    assert r.headers.get('WWW-Authenticate') == 'Negotiate'


def test_issue_rejects_failed_negotiation(client, wstep_kerberos_config, monkeypatch):
    monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
    monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
    monkeypatch.setattr(
        negotiate_auth, 'authenticate_negotiate',
        lambda auth_header, connection_key: negotiate_auth.NegotiateResult(status='failed', error='bad ticket'),
    )
    csr, _key = _make_csr()
    r = client.post(ISSUE_URL, data=_build_rst(csr), headers={'Authorization': 'Negotiate dG9rZW4='})
    assert r.status_code == 401


def test_issue_succeeds_with_authenticated_negotiation(client, app, wstep_kerberos_config, monkeypatch):
    monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
    monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
    monkeypatch.setattr(
        negotiate_auth, 'authenticate_negotiate',
        lambda auth_header, connection_key: _authenticated_result('bXV0dWFsLXRva2Vu'),
    )

    csr, key = _make_csr()
    r = client.post(
        ISSUE_URL, data=_build_rst(csr),
        headers={'Authorization': 'Negotiate dG9rZW4=', 'Content-Type': 'application/soap+xml'},
    )
    assert r.status_code == 200
    assert r.headers.get('WWW-Authenticate') == 'Negotiate bXV0dWFsLXRva2Vu'

    cert = _issued_cert_from_rstr(r.data)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()

    with app.app_context():
        log = (AuditLog.query
               .filter_by(action='certificate.issued', username=KERBEROS_PRINCIPAL)
               .order_by(AuditLog.id.desc())
               .first())
        assert log is not None


def _configure_ad_connector(app):
    with app.app_context():
        ADConnectorConfig.query.delete()
        config = ADConnectorConfig(
            server='dc1.hagland.domain', base_dn='DC=hagland,DC=domain',
            bind_dn='svc-ucm', enabled=True,
        )
        config.bind_password = 'irrelevant'
        db.session.add(config)
        db.session.commit()


def _clear_ad_derived_templates(app):
    """Remove any leftover ad_derived_subject template from an earlier test
    in this module-scoped app/db -- without this, a test asserting
    derivation is rejected when nothing has opted in could false-pass/fail
    depending on test execution order."""
    with app.app_context():
        CertificateTemplate.query.filter_by(name='Test AD User Template').delete()
        db.session.commit()


def _configure_ad_derived_user_template(app):
    """An active template with ad_derived_subject=True -- the per-template
    opt-in wstep_service._user_ad_derivation_enabled gates user-branch
    derivation on. Unpinned: _resolve_templates_for_ca falls back to every
    active template when a CA has nothing pinned, so this alone is enough
    to make the CA eligible."""
    with app.app_context():
        CertificateTemplate.query.filter_by(name='Test AD User Template').delete()
        template = CertificateTemplate(
            name='Test AD User Template', template_type='client_auth',
            extensions_template='{}', is_active=True, ad_derived_subject=True,
        )
        db.session.add(template)
        db.session.commit()


class TestNakedCsrSubjectDerivation:
    """Real Windows GPO machine autoenrollment submits a CSR with no CN and
    no SAN for machine templates, trusting the CA to derive the subject
    from AD -- see services/ad_connector/lookup.py and
    wstep_service.issue's kerberos_principal handling."""

    def test_naked_csr_with_successful_ad_lookup_gets_derived_subject(
        self, client, app, wstep_kerberos_config, monkeypatch
    ):
        _configure_ad_connector(app)
        monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
        monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
        monkeypatch.setattr(
            negotiate_auth, 'authenticate_negotiate',
            lambda auth_header, connection_key: _authenticated_result(),
        )
        monkeypatch.setattr(
            ad_lookup, 'lookup_computer_dns_hostname',
            lambda sam_account_name: 'win11.hagland.domain',
        )

        csr, key = _make_naked_csr()
        r = client.post(
            ISSUE_URL, data=_build_rst(csr),
            headers={'Authorization': 'Negotiate dG9rZW4=', 'Content-Type': 'application/soap+xml'},
        )
        assert r.status_code == 200

        cert = _issued_cert_from_rstr(r.data)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'win11.hagland.domain'
        assert cert.public_key().public_numbers() == key.public_key().public_numbers()

        with app.app_context():
            db_cert = Certificate.query.filter_by(serial_number=str(cert.serial_number)).first()
            assert db_cert is not None
            assert db_cert.subject_cn == 'win11.hagland.domain'

    def test_naked_csr_with_failed_ad_lookup_still_rejected(
        self, client, app, wstep_kerberos_config, monkeypatch
    ):
        _configure_ad_connector(app)
        monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
        monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
        monkeypatch.setattr(
            negotiate_auth, 'authenticate_negotiate',
            lambda auth_header, connection_key: _authenticated_result(),
        )
        monkeypatch.setattr(ad_lookup, 'lookup_computer_dns_hostname', lambda sam_account_name: None)

        csr, _key = _make_naked_csr()
        r = client.post(
            ISSUE_URL, data=_build_rst(csr),
            headers={'Authorization': 'Negotiate dG9rZW4=', 'Content-Type': 'application/soap+xml'},
        )
        assert r.status_code == 400

    # Golden reference: a real ADCS-issued User certificate pulled from the
    # lab (dc1.hagland.domain's "Active Directory Enrollment Policy",
    # enrolled interactively as roy.hagland). Confirms the exact subject
    # RDN order and UPN SAN shape a byte-equivalent UCM-issued cert must
    # reproduce -- ``Subject: CN=Roy Hagland, CN=Users, DC=hagland,
    # DC=domain`` / ``SAN: Other Name:Principal Name=roy.hagland@hagland.domain``.
    _GOLDEN_USER_DN_COMPONENTS = [
        ('CN', 'Roy Hagland'),
        ('CN', 'Users'),
        ('DC', 'hagland'),
        ('DC', 'domain'),
    ]
    _GOLDEN_USER_UPN = 'roy.hagland@hagland.domain'

    def test_naked_csr_from_user_principal_with_successful_ad_lookup_gets_derived_subject_and_upn(
        self, client, app, wstep_kerberos_config, monkeypatch
    ):
        """A user Kerberos principal (no trailing $) submitting a naked CSR
        gets a subject and SAN derived from AD, matching real ADCS's own
        User-template enrollment shape."""
        _configure_ad_connector(app)
        _configure_ad_derived_user_template(app)
        monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
        monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
        monkeypatch.setattr(
            negotiate_auth, 'authenticate_negotiate',
            lambda auth_header, connection_key: negotiate_auth.NegotiateResult(
                status='authenticated', client_principal='roy.hagland@HAGLAND.DOMAIN',
            ),
        )
        monkeypatch.setattr(
            ad_lookup, 'lookup_user_ad_identity',
            lambda sam_account_name: {
                'dn_components': self._GOLDEN_USER_DN_COMPONENTS,
                'upn': self._GOLDEN_USER_UPN,
            },
        )

        csr, key = _make_naked_csr()
        r = client.post(
            ISSUE_URL, data=_build_rst(csr),
            headers={'Authorization': 'Negotiate dG9rZW4=', 'Content-Type': 'application/soap+xml'},
        )
        assert r.status_code == 200

        cert = _issued_cert_from_rstr(r.data)
        assert cert.public_key().public_numbers() == key.public_key().public_numbers()

        # rfc4514_string() is leaf-first (RFC4514/LDAP display convention,
        # matching how AD's own distinguishedName and PowerShell's cert
        # Subject display read) -- byte-for-byte the golden ADCS cert's
        # own displayed subject. The underlying DER SEQUENCE order is the
        # reverse (root-first); see wstep_service._x509_name_from_dn_components.
        assert cert.subject.rfc4514_string() == 'CN=Roy Hagland,CN=Users,DC=hagland,DC=domain'

        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert extract_upns_from_san_list(list(san_ext.value)) == [self._GOLDEN_USER_UPN]

        with app.app_context():
            db_cert = Certificate.query.filter_by(serial_number=str(cert.serial_number)).first()
            assert db_cert is not None
            assert db_cert.subject_cn == 'Roy Hagland'
            assert json.loads(db_cert.san_upn) == [self._GOLDEN_USER_UPN]

    def test_naked_csr_from_user_with_mail_attribute_includes_email(
        self, client, app, wstep_kerberos_config, monkeypatch
    ):
        """A user AD object with a mail attribute gets it included as a
        leaf-most subject RDN and an SAN RFC822Name -- opportunistic, never
        a hard requirement (unlike real ADCS's CT_FLAG_SUBJECT_REQUIRE_EMAIL,
        which would decline enrollment outright for any user without one)."""
        _configure_ad_connector(app)
        _configure_ad_derived_user_template(app)
        monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
        monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
        monkeypatch.setattr(
            negotiate_auth, 'authenticate_negotiate',
            lambda auth_header, connection_key: negotiate_auth.NegotiateResult(
                status='authenticated', client_principal='roy.hagland@HAGLAND.DOMAIN',
            ),
        )
        monkeypatch.setattr(
            ad_lookup, 'lookup_user_ad_identity',
            lambda sam_account_name: {
                'dn_components': self._GOLDEN_USER_DN_COMPONENTS,
                'upn': self._GOLDEN_USER_UPN,
                'mail': self._GOLDEN_USER_UPN,
            },
        )

        csr, key = _make_naked_csr()
        r = client.post(
            ISSUE_URL, data=_build_rst(csr),
            headers={'Authorization': 'Negotiate dG9rZW4=', 'Content-Type': 'application/soap+xml'},
        )
        assert r.status_code == 200

        cert = _issued_cert_from_rstr(r.data)
        subject_attrs = list(cert.subject)
        assert subject_attrs[-1].oid == NameOID.EMAIL_ADDRESS
        assert subject_attrs[-1].value == self._GOLDEN_USER_UPN
        # CN extraction ([-1] of COMMON_NAME-typed attrs specifically) must
        # stay unaffected by the trailing email RDN, which is a different
        # attribute type entirely.
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[-1].value == 'Roy Hagland'

        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert extract_upns_from_san_list(list(san_ext.value)) == [self._GOLDEN_USER_UPN]
        assert list(san_ext.value.get_values_for_type(x509.RFC822Name)) == [self._GOLDEN_USER_UPN]

        with app.app_context():
            db_cert = Certificate.query.filter_by(serial_number=str(cert.serial_number)).first()
            assert db_cert is not None
            assert db_cert.subject_cn == 'Roy Hagland'
            assert json.loads(db_cert.san_email) == [self._GOLDEN_USER_UPN]

    def test_naked_csr_from_user_principal_with_failed_ad_lookup_still_rejected(
        self, client, app, wstep_kerberos_config, monkeypatch
    ):
        """Same fail-closed guarantee as the machine path: no AD identity
        found (account missing, no userPrincipalName, LDAP unreachable,
        ...) means the naked CSR falls through to the pre-existing
        rejection, never a crash or a bypass."""
        _configure_ad_connector(app)
        _configure_ad_derived_user_template(app)
        monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
        monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
        monkeypatch.setattr(
            negotiate_auth, 'authenticate_negotiate',
            lambda auth_header, connection_key: negotiate_auth.NegotiateResult(
                status='authenticated', client_principal='alice@HAGLAND.DOMAIN',
            ),
        )
        monkeypatch.setattr(ad_lookup, 'lookup_user_ad_identity', lambda sam_account_name: None)

        csr, _key = _make_naked_csr()
        r = client.post(
            ISSUE_URL, data=_build_rst(csr),
            headers={'Authorization': 'Negotiate dG9rZW4=', 'Content-Type': 'application/soap+xml'},
        )
        assert r.status_code == 400

    def test_naked_csr_from_user_principal_rejected_when_no_template_opted_in(
        self, client, app, wstep_kerberos_config, monkeypatch
    ):
        """The per-template toggle is the gate, not just AD Connector config
        + a successful lookup -- without any ad_derived_subject template,
        derivation must not fire even if AD would have resolved the user."""
        _configure_ad_connector(app)
        _clear_ad_derived_templates(app)
        monkeypatch.setattr(negotiate_auth, 'is_library_available', lambda: True)
        monkeypatch.setattr(negotiate_auth, 'is_configured', lambda: True)
        monkeypatch.setattr(
            negotiate_auth, 'authenticate_negotiate',
            lambda auth_header, connection_key: negotiate_auth.NegotiateResult(
                status='authenticated', client_principal='roy.hagland@HAGLAND.DOMAIN',
            ),
        )
        monkeypatch.setattr(
            ad_lookup, 'lookup_user_ad_identity',
            lambda sam_account_name: {
                'dn_components': self._GOLDEN_USER_DN_COMPONENTS,
                'upn': self._GOLDEN_USER_UPN,
            },
        )

        csr, _key = _make_naked_csr()
        r = client.post(
            ISSUE_URL, data=_build_rst(csr),
            headers={'Authorization': 'Negotiate dG9rZW4=', 'Content-Type': 'application/soap+xml'},
        )
        assert r.status_code == 400
