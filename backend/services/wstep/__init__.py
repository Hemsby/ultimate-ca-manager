"""MS-WSTEP (WS-Trust X.509v3 Token Enrollment Extensions) support.

Path constants live here (rather than only in ``api/wstep_protocol.py``) so
``services/xcep/policy_builder.py`` can advertise them via CAURI without a
circular import between the XCEP and WSTEP API modules.
"""

# Real ADCS CES naming convention: <name>_CES_<AuthType>/service.svc. UCM has
# no per-CA "friendly name" prefix concept the way ADCS does, so a single
# fixed service name is used for both auth bindings this implementation
# currently supports.
CES_USERNAME_PASSWORD_PATH = '/ADCertificateService_CES_UsernamePassword/service.svc'
CES_CERTIFICATE_PATH = '/ADCertificateService_CES_Certificate/service.svc'
