"""Regression tests for the XCEP/WSTEP protocol-path exemptions.

CEP/CES paths (real Windows SOAP clients) must never be treated as admin
UI: the canonical-host redirect middleware 302s admin UI paths whenever a
base_url is configured, and Windows SOAP clients don't follow POST
redirects — a request that gets redirected here just breaks enrollment.
Same reasoning applies to CSRF, since these clients have no session/token
to present. No Flask app context needed: both functions under test are
pure path-prefix checks.
"""
from security.csrf import CSRFProtection
from utils.public_endpoints import is_admin_ui_path, is_protocol_path

_CEP_CES_PATHS = (
    '/ADPolicyProvider_CEP_UsernamePassword/service.svc',
    '/ADPolicyProvider_CEP_Kerberos/service.svc',
    '/ADCertificateService_CES_UsernamePassword/service.svc',
    '/ADCertificateService_CES_Certificate/service.svc',
    '/ADCertificateService_CES_Kerberos/service.svc',
)


def test_is_protocol_path_covers_cep_ces():
    for path in _CEP_CES_PATHS:
        assert is_protocol_path(path), f'{path} must be recognized as a protocol path'


def test_is_admin_ui_path_excludes_cep_ces():
    for path in _CEP_CES_PATHS:
        assert not is_admin_ui_path(path), f'{path} must not be treated as admin UI'


def test_csrf_exempt_covers_cep_ces():
    for path in _CEP_CES_PATHS:
        assert CSRFProtection.is_exempt(path), f'{path} must be CSRF-exempt'
