"""
MS-WSTEP orchestration: RST -> issued/renewed certificate.

The WSTEP analogue of ``services/scep/scep_service.py`` — protocol
orchestration kept separate from wire-format parsing (``rst_parser.py``),
signature verification (``ws_security.py``), and response construction
(``rstr_builder.py``). Both entry points call
``CAService.sign_csr_from_crypto`` directly for the actual issuance,
following EST's pattern (``api/est_protocol.py``'s ``simpleenroll``/
``simplereenroll``) rather than SCEP's inlined ``x509.CertificateBuilder``
tech debt.
"""
import logging

from cryptography import x509
from cryptography.x509.oid import NameOID

from models import Certificate
from services.ca_service import CAService
from utils.datetime_utils import utc_now
from utils.key_type import validate_enrollment_public_key
from utils.san_parse import is_valid_san_email
from utils.upn_san import build_upn_other_name

from . import ws_security

logger = logging.getLogger(__name__)

# AD DN RDN attribute names (as ldap3's parse_dn returns them from a real
# AD distinguishedName) -> the x509.Name attribute OID they map to. Covers
# the components a real ADCS User certificate's directory-path subject
# uses (confirmed in the lab: CN=Roy Hagland, CN=Users, DC=hagland,
# DC=domain) plus the other standard DN attributes AD may plausibly return.
_DN_ATTR_OIDS = {
    'CN': NameOID.COMMON_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'DC': NameOID.DOMAIN_COMPONENT,
    'L': NameOID.LOCALITY_NAME,
    'S': NameOID.STATE_OR_PROVINCE_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'C': NameOID.COUNTRY_NAME,
}


def _x509_name_from_dn_components(dn_components, email=None):
    """Build an x509.Name from AD DN RDN components (attr, value) pairs.

    ``dn_components`` arrives leaf-to-root (AD's own ``distinguishedName``
    string order, e.g. ``[('CN', 'Roy Hagland'), ('CN', 'Users'), ('DC',
    'hagland'), ('DC', 'domain')]``) -- but ``x509.Name`` expects attributes
    in root-to-leaf (DER SEQUENCE) order and reverses internally for RFC4514
    display. Confirmed empirically: building ``x509.Name`` directly from
    AD's leaf-first order produces ``rfc4514_string()`` == "DC=domain,
    DC=hagland,CN=Users,CN=Roy Hagland" -- backwards from the real
    ADCS-issued cert's own "CN=Roy Hagland, CN=Users, DC=hagland,
    DC=domain". The components must be reversed here, once, or every
    AD-derived user subject silently comes out RDN-reversed.

    ``email``, when given, is appended last (i.e. most-specific/leaf-most
    in RFC4514 display: "E=roy.hagland@hagland.domain,CN=Roy
    Hagland,..."), the conventional placement for an emailAddress RDN.
    Optional -- see ``lookup_user_ad_identity``'s docstring for why a
    missing AD ``mail`` attribute must never block subject derivation.

    None if any DN component's attribute type isn't recognized -- fail
    closed rather than silently dropping or mis-mapping a component real
    ADCS would have included.
    """
    attrs = []
    for attr_name, value in reversed(dn_components):
        oid = _DN_ATTR_OIDS.get(attr_name.upper())
        if oid is None:
            logger.warning(
                "AD Connector: unrecognized DN attribute %r building subject "
                "from AD -- refusing to derive a partial subject", attr_name,
            )
            return None
        attrs.append(x509.NameAttribute(oid, value))
    if not attrs:
        return None
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)

# ``cryptography``'s CertificateSigningRequest.is_signature_valid reports
# False for a SHA-1-signed CSR even when the signature is mathematically
# valid (confirmed by verifying the same signature manually with
# public_key.verify(..., hashes.SHA1())) -- it isn't reporting tampering,
# it's refusing to vouch for a weak hash algorithm. Windows' certreq.exe
# defaults to SHA-1 unless an INF explicitly sets HashAlgorithm=sha256, so
# this is a real, common case worth a specific message rather than the
# generic "signature invalid" one, which reads as if the request were
# corrupted.
_WEAK_CSR_HASH_ALGORITHMS = {'md5', 'sha1'}


def _weak_csr_hash_algorithm(csr):
    """The CSR's signature hash algorithm name, if it's one of the weak
    ones ``is_signature_valid`` refuses to validate. None otherwise
    (including when the algorithm can't be determined at all, e.g. Ed25519)."""
    try:
        algo = csr.signature_hash_algorithm
    except Exception:
        return None
    if algo is not None and algo.name in _WEAK_CSR_HASH_ALGORITHMS:
        return algo.name
    return None


def _is_naked_csr(csr):
    """No CN and no SubjectAlternativeName at all -- what real Windows GPO
    machine autoenrollment deliberately submits for machine templates,
    trusting the CA to derive the subject from AD (see
    ``issue``'s ``kerberos_principal`` handling and
    ``services/ad_connector/lookup.py``). Factored out of ``_validate_csr``
    so ``issue()`` can check the same condition directly, rather than
    string-matching ``_validate_csr``'s error message."""
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    has_cn = bool(cn_attrs and str(cn_attrs[0].value).strip())
    return not has_cn and _san_values(csr) is None


def _validate_csr(csr, require_pop=True, allow_naked_subject=False):
    """Similar to EST's ``_validate_est_csr``: proof of possession,
    subject identity present, key-strength policy. Reimplemented locally
    rather than extracted into a shared module, matching the existing
    precedent that EST and SCEP each keep their own copy.

    Two deliberate differences from EST:

    - ``require_pop=False`` skips the self-signature check. Real Windows
      "Full PKCS#7" requests (see ``rst_parser._unwrap_pkcs7_csr``) embed
      a PKCS#10 CertificationRequest whose own self-signature does not
      reliably verify — proof of possession there is meant to come from
      the *outer* CMS SignedData's signature instead. Verifying that
      outer signature against a trusted identity is not implemented here,
      so CMC-wrapped requests currently have no cryptographic PoP check
      at all. Flagged clearly rather than silently assumed secure.
    - An empty Subject is accepted when the CSR carries a
      SubjectAlternativeName instead (SAN-only identity is standard
      modern TLS practice).

    ``allow_naked_subject``: skip the "must have CN or SAN" check -- only
    set by ``issue()`` when it has *already* independently derived a
    replacement subject via the AD Connector for a Kerberos machine
    principal. Every other check (PoP, key strength) still applies
    unconditionally regardless of this flag; a naked CSR never gets a free
    pass on those.

    Returns an error string, or None if the CSR is acceptable.
    """
    if require_pop:
        try:
            signature_valid = csr.is_signature_valid
        except Exception:
            signature_valid = False
        if not signature_valid:
            weak_algo = _weak_csr_hash_algorithm(csr)
            if weak_algo:
                return (
                    f'CSR signed with an unsupported hash algorithm ({weak_algo}); '
                    'use SHA-256 or stronger'
                )
            return 'CSR signature invalid (proof of possession failed)'

    if not allow_naked_subject and _is_naked_csr(csr):
        return 'CSR subject must include a non-empty CN or a SubjectAltName'

    key_err = validate_enrollment_public_key(csr.public_key())
    if key_err:
        return key_err

    return None


def _san_values(cert_or_csr):
    """SAN entries as a set of (type, value) pairs — mirrors EST's
    ``_san_values``, order/criticality irrelevant to identity match."""
    try:
        ext = cert_or_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    return {(type(name).__name__, str(getattr(name, 'value', name))) for name in ext.value}


def _san_matches(signing_cert, csr):
    """Mirrors EST's ``_reenroll_san_matches``: a CSR without SAN is
    accepted (tolerant of clients that omit it), but a CSR that does
    include SAN must match the signing certificate's SAN exactly."""
    csr_sans = _san_values(csr)
    if csr_sans is None:
        return True
    cert_sans = _san_values(signing_cert) or set()
    return csr_sans == cert_sans


def _load_csr(csr_der):
    try:
        return x509.load_der_x509_csr(csr_der), None
    except Exception:
        return None, 'Invalid CSR encoding'


def _match_template_oid(ca, csr):
    """Best-effort match of the CSR's requested EKU against the CA's
    advertised templates (the same set XCEP's GetPolicies exposed), to
    pick which template's OID to stamp on the issued cert via
    ``ms_certificate_template_oid`` (see csr_operations_mixin's
    ``_certificate_template_extension`` — a real Windows client fails
    CX509Enrollment::Enroll with CERTSRV_E_PROPERTY_EMPTY when the issued
    cert carries no Certificate Template extension).

    There is no explicit "which template did you pick" signal in the RST
    or CSR to key off instead: a real captured Windows request's CMC
    control_sequence was empty and the CSR carried no separate
    CertificateTemplateName attribute. So this infers the template from
    what the CSR itself asks for (its EKU set).

    This is a real limitation, not a corner case: two templates can
    legitimately want the same EKU (e.g. "Web Server" and "VPN Server"
    both want serverAuth-only), and ties break on lowest template id —
    arbitrary but deterministic. Returns None (extension omitted
    entirely) if nothing matches at all.
    """
    try:
        import json

        from models import CertificateTemplate
        from services.xcep.policy_builder import _EKU_OIDS, _policy_oid_for_template, _resolve_templates_for_ca
    except Exception:
        return None

    all_active = CertificateTemplate.query.filter_by(is_active=True).all()
    candidates = _resolve_templates_for_ca(ca, all_active)
    if not candidates:
        return None

    try:
        csr_eku = {
            oid.dotted_string
            for oid in csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        }
    except x509.ExtensionNotFound:
        csr_eku = set()

    best, best_score = None, -1
    for template in candidates:
        try:
            parsed = json.loads(template.extensions_template or '{}')
        except (TypeError, ValueError):
            parsed = {}
        names = parsed.get('extended_key_usage') if isinstance(parsed, dict) else None
        template_eku = {
            _EKU_OIDS[name] for name in (names or []) if name in _EKU_OIDS
        }
        score = len(csr_eku & template_eku) - len(template_eku - csr_eku)
        if score > best_score or (score == best_score and best is not None and template.id < best.id):
            best, best_score = template, score

    if best is None or best_score < 0:
        return None
    return _policy_oid_for_template(ca, best)


def _user_ad_derivation_enabled(ca):
    """Whether any template resolvable for ``ca`` has opted into
    AD-derived user subjects (``CertificateTemplate.ad_derived_subject``).

    Deliberately independent of ``_match_template_oid``'s EKU-based
    scoring above: a naked CSR (the only kind this ever applies to — see
    ``issue()``) carries no EKU extension, so it scores negative against
    any candidate template that declares EKUs at all, meaning EKU-based
    matching alone would almost always find nothing and this feature would
    silently never fire. This only asks "did an admin opt any template
    into AD-derivation for this CA," mirroring how the machine branch below
    has no template dependency either — MS-WSTEP's wire protocol has no
    template-selection signal to check instead (see ``_match_template_oid``'s
    docstring).
    """
    try:
        from models import CertificateTemplate
        from services.xcep.policy_builder import _resolve_templates_for_ca
    except Exception:
        return False

    all_active = CertificateTemplate.query.filter_by(is_active=True).all()
    candidates = _resolve_templates_for_ca(ca, all_active)
    return any(getattr(t, 'ad_derived_subject', False) for t in candidates)


def issue(ca, csr_der, validity_days, source='wstep', require_pop=True, kerberos_principal=None):
    """UsernamePassword-bound initial enrollment. Returns (cert_pem, error).

    ``require_pop=False`` is passed by ``wstep_protocol.py`` when the CSR
    was unwrapped from a PKCS#7/CMC envelope (``ParsedRST.was_pkcs7_wrapped``)
    — see ``_validate_csr`` for why that inner CSR's self-signature can't
    be relied on for real Windows clients.

    ``kerberos_principal``: the authenticated Kerberos principal, e.g.
    ``'WIN11$@HAGLAND.DOMAIN'`` (machine) or ``'roy.hagland@HAGLAND.DOMAIN'``
    (user) -- passed *only* by the Kerberos-bound CES route (never the
    UsernamePassword one, which has no Kerberos identity to give). When set
    and the CSR is naked (see ``_is_naked_csr``), attempts to derive a
    subject via the AD Connector (``services/ad_connector/lookup.py``)
    instead of rejecting outright -- what real Windows GPO autoenrollment
    needs, since it deliberately submits a subject-less CSR for templates
    configured to build the subject from AD, trusting the CA to fill it in
    server-side the same way real ADCS does:

    - Machine principal: ``CN=<computer's AD dnsHostName>``, no SAN needed
      (the certificate's own CN synthesizes a matching SAN downstream).
      Unconditional on any template -- MS-WSTEP has no template-selection
      signal to gate it on (see ``_match_template_oid``'s docstring), and
      this is the already lab-verified path; it must not gain a new
      failure mode from the toggle below.
    - User principal: the AD user object's own directory-path DN as the
      subject, plus its ``userPrincipalName`` as a SAN OtherName -- matches
      a real ADCS-issued User certificate's shape exactly (confirmed
      against the lab: ``CN=Roy Hagland, CN=Users, DC=hagland, DC=domain``
      + ``Other Name:Principal Name=roy.hagland@hagland.domain``). Only
      attempted when at least one template resolvable for ``ca`` has opted
      in via ``CertificateTemplate.ad_derived_subject`` (see
      ``_user_ad_derivation_enabled``) -- unlike the machine path, this is
      new behavior, so it's admin opt-in per template rather than always-on.
      If the AD user object also has a ``mail`` attribute, it's added as a
      leaf-most ``E=`` subject RDN and an SAN RFC822Name -- opportunistic,
      never required: real ADCS's own CT_FLAG_SUBJECT_REQUIRE_EMAIL hard-
      declines autoenrollment for any user without one, which would make a
      single template unusable for a mixed user base, so UCM never
      advertises that requirement (see policy_builder.py's
      ``_USER_AD_DERIVED_SUBJECT_NAME_FLAGS``) and simply includes the
      email when present, omits it otherwise.

    Falls through to the normal naked-CSR rejection if the connector isn't
    configured, no template has opted in, or the lookup fails for any
    reason (account not found, LDAP unreachable, no userPrincipalName
    set, ...).
    """
    csr, err = _load_csr(csr_der)
    if err:
        return None, err

    override_subject = None
    override_san = None
    if kerberos_principal and _is_naked_csr(csr):
        from services.ad_connector import lookup
        parsed = lookup.parse_kerberos_principal(kerberos_principal)
        if parsed:
            sam_account_name, _realm = parsed
            if lookup.is_machine_principal(kerberos_principal):
                dns_hostname = lookup.lookup_computer_dns_hostname(sam_account_name)
                if dns_hostname:
                    override_subject = x509.Name(
                        [x509.NameAttribute(NameOID.COMMON_NAME, dns_hostname)]
                    )
            elif _user_ad_derivation_enabled(ca):
                identity = lookup.lookup_user_ad_identity(sam_account_name)
                if identity:
                    # AD's mail attribute is optional -- validated (not just
                    # truthy) before use, since it's untrusted directory
                    # data reaching straight into a certificate subject/SAN.
                    # A malformed value degrades to "no email", never a
                    # crash or a bogus RDN.
                    email = identity.get('mail')
                    if email and not is_valid_san_email(email):
                        logger.warning(
                            "AD Connector: ignoring malformed mail attribute %r for %r",
                            email, sam_account_name,
                        )
                        email = None
                    derived_subject = _x509_name_from_dn_components(identity['dn_components'], email=email)
                    if derived_subject is not None:
                        override_subject = derived_subject
                        override_san = [build_upn_other_name(identity['upn'])]
                        if email:
                            override_san.append(x509.RFC822Name(email))

    err = _validate_csr(
        csr, require_pop=require_pop, allow_naked_subject=override_subject is not None
    )
    if err:
        return None, err

    try:
        cert_pem, _serial = CAService.sign_csr_from_crypto(
            ca=ca, csr=csr, validity_days=validity_days, source=source,
            require_pop=require_pop,
            ms_certificate_template_oid=_match_template_oid(ca, csr),
            override_subject=override_subject,
            override_san=override_san,
        )
    except Exception as e:
        logger.error('WSTEP issue failed: %s', e)
        return None, 'Certificate issuance failed'

    return cert_pem, None


def renew(ca, csr_der, security_header, validity_days, source='wstep', require_pop=True):
    """Certificate-bound renewal: the RST is signed with the client's
    current certificate's private key. Returns (cert_pem, error).

    ``require_pop`` — see ``issue()``; renewal RSTs can arrive PKCS#7/CMC-
    wrapped too, and the outer WS-Security signature already authenticates
    the caller here, so the inner CSR's own self-signature matters even
    less than it does for the UsernamePassword-bound issue path.
    """
    try:
        signing_cert_der = ws_security.verify_signed_request(security_header)
    except ws_security.WSSecurityError as e:
        return None, str(e)

    try:
        signing_cert = x509.load_der_x509_certificate(signing_cert_der)
    except Exception:
        return None, 'Invalid signing certificate'

    # Signature verification only proves possession of the private key —
    # it does not establish trust. Confirm this is a certificate UCM
    # itself issued, and that it's still usable, before treating it as an
    # authenticated identity.
    db_cert = Certificate.query.filter_by(
        serial_number=str(signing_cert.serial_number)
    ).first()
    if not db_cert or not db_cert.crt:
        return None, 'Signing certificate is not recognized'
    if db_cert.revoked:
        return None, 'Signing certificate has been revoked'
    if db_cert.valid_to and db_cert.valid_to < utc_now():
        return None, 'Signing certificate has expired'

    csr, err = _load_csr(csr_der)
    if err:
        return None, err

    err = _validate_csr(csr, require_pop=require_pop)
    if err:
        return None, err

    if signing_cert.subject != csr.subject:
        return None, 'CSR subject does not match signing certificate'
    if not _san_matches(signing_cert, csr):
        return None, 'CSR SubjectAltName does not match signing certificate'

    try:
        cert_pem, _serial = CAService.sign_csr_from_crypto(
            ca=ca, csr=csr, validity_days=validity_days, source=source,
            renewal_of=signing_cert, require_pop=require_pop,
            ms_certificate_template_oid=_match_template_oid(ca, csr),
        )
    except Exception as e:
        logger.error('WSTEP renew failed: %s', e)
        return None, 'Certificate renewal failed'

    return cert_pem, None
