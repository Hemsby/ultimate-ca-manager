"""
CSR operations mixin for TrustStoreService
"""
import ipaddress
import logging
from datetime import timedelta
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from utils.datetime_utils import utc_now, cert_not_before
from utils.x509_aki import authority_key_identifier_from_issuer
from .constants import HASH_ALGORITHMS
from .key_operations_mixin import KeyOperationsMixin
from .constraints_mixin import ConstraintsMixin

logger = logging.getLogger(__name__)


_LEAF_CA_ONLY_EXTENSION_OIDS = frozenset({
    ExtensionOID.NAME_CONSTRAINTS,
    ExtensionOID.POLICY_CONSTRAINTS,
    ExtensionOID.INHIBIT_ANY_POLICY,
})

# EKUs a leaf cert signed from a CSR must never carry: an OCSPSigning leaf that
# chains to the CA is trusted by validators as a delegated OCSP responder for
# the whole CA (it can sign "good" for revoked certs), and timeStamping grants
# trusted-timestamp authority. Neither may be obtained by a protocol client
# (ACME/EST) that only proved domain control or mTLS. Admin-configured delegated
# responders are issued through the dedicated certificate-creation path, not here.
_LEAF_FORBIDDEN_EKU_OIDS = frozenset({
    x509.ExtendedKeyUsageOID.OCSP_SIGNING,
    x509.ExtendedKeyUsageOID.TIME_STAMPING,
})

# anyExtendedKeyUsage defeats EKU chaining entirely: a leaf carrying it is
# usable for every purpose, which makes any per-type EKU policy meaningless.
# Never honoured from a CSR on any protocol path (ACME/EST/renewal). NB: the
# admin Sign-CSR endpoints pass allow_sensitive_ekus=True and are deliberately
# uncapped (explicit operator intent), so this block-list does not apply there.
_ANY_EKU_OID = x509.ObjectIdentifier('2.5.29.37.0')

# Microsoft Smartcard Logon — grants Active Directory interactive logon when
# paired with a UPN SAN. Never honoured from CSR-supplied EKU on a protocol
# path (same admin-path caveat as above); an operator who genuinely wants it
# passes it explicitly via ``extra_ekus``.
_SMARTCARD_LOGON_OID = x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.2')

# Per-certificate-type EKU ceiling for CSR-supplied Extended Key Usage.
#
# Without this, whatever EKU a CSR carries is copied onto the leaf, so a client
# that only proved DNS control (ACME finalize signs with cert_type
# 'server_cert') could mint a codeSigning or emailProtection certificate. The
# resolved certificate type — not the requester's CSR — decides what the leaf
# may be used for. Operator-supplied ``extra_ekus`` are deliberate admin intent
# and are merged in separately, so they are not capped here.
_TLS_EKUS = frozenset({
    x509.ExtendedKeyUsageOID.SERVER_AUTH,
    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
})
_CERT_TYPE_ALLOWED_EKUS = {
    'server_cert': _TLS_EKUS,
    'server': _TLS_EKUS,
    'host': _TLS_EKUS,
    'client_cert': _TLS_EKUS,
    'usr_cert': _TLS_EKUS,
    'user': _TLS_EKUS,
    'combined_cert': _TLS_EKUS,
    'combined_server_client': _TLS_EKUS,
    'code_signing': frozenset({x509.ExtendedKeyUsageOID.CODE_SIGNING}),
    'email_cert': frozenset({
        x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
        x509.ExtendedKeyUsageOID.CLIENT_AUTH,
    }),
    # EST device enrollment — same reviewed allow-list SCEP applies to its
    # protocol enrollees (scep_service._ALLOWED_EKU_OIDS): both protocols
    # enroll the same kinds of devices, and a narrower EST ceiling silently
    # strips EKUs (e.g. ipsecIKE on a VPN gateway) that the equivalent SCEP
    # enrollment would keep.
    'device_cert': frozenset({
        x509.ExtendedKeyUsageOID.SERVER_AUTH,
        x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
        x509.ExtendedKeyUsageOID.CODE_SIGNING,
        x509.ExtendedKeyUsageOID.IPSEC_IKE,
    }),
}


def _default_ekus_for_cert_type(cert_type):
    """The EKU profile a leaf of *cert_type* carries when its CSR supplies no
    usable EKU.

    Shared by the no-EKU-in-CSR default and the every-EKU-refused fallback in
    ``_filter_csr_ekus`` so both shapes resolve to the same profile: a CSR
    that requests nothing and a CSR whose every request is refused must not
    end up with different key purposes. Types without a profile (e.g. the
    deliberate ``custom`` type) return an empty list.
    """
    if cert_type in ('server_cert', 'server', 'host'):
        return [x509.ExtendedKeyUsageOID.SERVER_AUTH]
    if cert_type in ('usr_cert', 'client_cert', 'user'):
        return [x509.ExtendedKeyUsageOID.CLIENT_AUTH]
    if cert_type in ('combined_server_client', 'combined_cert', 'device_cert'):
        return [
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]
    if cert_type == 'code_signing':
        return [x509.ExtendedKeyUsageOID.CODE_SIGNING]
    if cert_type == 'email_cert':
        return [x509.ExtendedKeyUsageOID.EMAIL_PROTECTION]
    return []


def _filter_csr_ekus(eku_oids, cert_type, allow_sensitive_ekus, renewal_of=None):
    """Cap CSR-supplied EKUs for a leaf to what *cert_type* permits.

    Returns (kept, dropped).

    ``allow_sensitive_ekus`` marks the admin Sign-CSR path — an operator with
    full CA control deliberately signing a CSR (e.g. a delegated OCSP responder
    or TSA). That is explicit human intent, so no ceiling is applied and the
    path behaves exactly as before. Every protocol path (ACME finalize, EST,
    SCEP, auto-renewal) leaves it False and gets the full cap: an enrollee that
    only proved domain control cannot widen its own leaf's key purposes.

    ``renewal_of`` is the certificate this signing renews. EKUs it already
    carries stay allowed (renewal at par): silently stripping them — e.g.
    ipsecIKE on a VPN device renewing over EST — breaks the service downstream
    with no error anywhere, which is the same reason SCEP preserves them
    (scep_service). The block-list above still applies, so OCSPSigning,
    timeStamping, anyExtendedKeyUsage and Smartcard Logon are never
    resurrected from a prior certificate.

    When every requested EKU is refused, the certificate type's own profile is
    issued instead: omitting the ExtendedKeyUsage extension entirely would
    make the leaf unrestricted for every purpose (RFC 5280 §4.2.1.12) —
    strictly weaker than the cap, and weaker than the same CSR with no EKU at
    all. A type with no profile to fall back to refuses outright.
    """
    if allow_sensitive_ekus:
        return list(eku_oids), []

    allowed = _CERT_TYPE_ALLOWED_EKUS.get(cert_type)
    if allowed is not None and renewal_of is not None:
        try:
            prior = set(renewal_of.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            ).value)
        except x509.ExtensionNotFound:
            prior = set()
        extra = {
            oid for oid in prior - allowed
            if oid not in _LEAF_FORBIDDEN_EKU_OIDS
            and oid not in (_ANY_EKU_OID, _SMARTCARD_LOGON_OID)
        }
        if extra:
            logger.info(
                "sign_csr: renewal at par — keeping prior EKU(s) %s beyond "
                "the %r profile",
                sorted(o.dotted_string for o in extra), cert_type,
            )
            allowed = allowed | extra

    kept, dropped = [], []
    for oid in eku_oids:
        if oid in _LEAF_FORBIDDEN_EKU_OIDS or oid in (_ANY_EKU_OID, _SMARTCARD_LOGON_OID):
            dropped.append(oid)
            continue
        # Unknown/custom certificate types keep their historical behaviour:
        # no per-type ceiling, only the block-list above applies.
        if allowed is not None and oid not in allowed:
            dropped.append(oid)
            continue
        kept.append(oid)

    if not kept:
        # Every requested EKU was refused. Emitting no ExtendedKeyUsage
        # extension would hand back an unrestricted certificate — and create
        # the perverse incentive that a CSR requesting a forbidden EKU gets
        # MORE than a CSR requesting nothing. Fall back to the type's profile.
        kept = _default_ekus_for_cert_type(cert_type)
        if not kept:
            raise ValueError(
                "CSR requests only Extended Key Usages that are not permitted "
                f"for certificate type {cert_type!r}"
            )
    return kept, dropped


def _capped_basic_constraints(csr_constraints, ca_cert):
    """Clamp a sub-CA's pathLenConstraint to what the parent CA permits.

    RFC 5280 §4.2.1.9: a CA with pathLenConstraint N may be followed by at most
    N further CAs in the chain, so a child issued by it may assert at most N-1;
    a parent with pathLen 0 may not issue a sub-CA at all. The value otherwise
    comes straight from the requester's CSR, so without this clamp a signed
    intermediate could claim a deeper (or unlimited) path than its issuer.
    """
    requested = csr_constraints.path_length

    try:
        parent_bc = ca_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        parent_limit = parent_bc.path_length
    except x509.ExtensionNotFound:
        parent_limit = None

    if parent_limit is None:
        # Unconstrained parent — the child's own request stands.
        return csr_constraints

    if parent_limit <= 0:
        raise ValueError(
            "Issuing CA has pathLenConstraint 0 and may not issue a subordinate CA"
        )

    max_allowed = parent_limit - 1
    if requested is None or requested > max_allowed:
        if requested is not None:
            logger.warning(
                "clamping requested sub-CA pathLenConstraint %s to %s "
                "(issuing CA permits %s)", requested, max_allowed, parent_limit,
            )
        return x509.BasicConstraints(ca=True, path_length=max_allowed)

    return csr_constraints


def capped_path_length(requested, parent_cert):
    """Clamp a sub-CA pathLenConstraint to what *parent_cert* permits.

    Public entry point for the create-CA path (POST /api/v2/cas), so both
    routes that mint a sub-CA at the same permission level enforce the same
    RFC 5280 §4.2.1.9 rule with the same error string. Returns the clamped
    value; raises ValueError when the parent may not issue a sub-CA at all.
    """
    return _capped_basic_constraints(
        x509.BasicConstraints(ca=True, path_length=requested), parent_cert
    ).path_length


def _key_usage_with_ca_signing(usage, enabled):
    """Return a KeyUsage with CA signing bits forced to the policy value."""
    return x509.KeyUsage(
        digital_signature=usage.digital_signature,
        content_commitment=usage.content_commitment,
        key_encipherment=usage.key_encipherment,
        data_encipherment=usage.data_encipherment,
        key_agreement=usage.key_agreement,
        key_cert_sign=enabled,
        crl_sign=enabled,
        encipher_only=usage.encipher_only if usage.key_agreement else False,
        decipher_only=usage.decipher_only if usage.key_agreement else False,
    )


class CSROperationsMixin:
    """CSR generation and signing operations mixin"""

    @staticmethod
    def generate_csr(
        subject: x509.Name,
        key_type: str = '2048',
        digest: str = 'sha256',
        san_dns: Optional[List[str]] = None,
        san_ip: Optional[List[str]] = None,
        san_email: Optional[List[str]] = None,
        san_uri: Optional[List[str]] = None,
        san_upn: Optional[List[str]] = None,
    ) -> Tuple[bytes, bytes]:
        """Generate a Certificate Signing Request."""
        # Generate private key
        private_key = KeyOperationsMixin.generate_private_key(key_type)

        # Build CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)

        # Add SANs if provided
        san_list = []
        if san_dns:
            san_list.extend([x509.DNSName(dns) for dns in san_dns])
        if san_ip:
            san_list.extend([
                x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ip
            ])
        if san_email:
            san_list.extend([x509.RFC822Name(email) for email in san_email])
        if san_uri:
            san_list.extend([x509.UniformResourceIdentifier(uri) for uri in san_uri])
        if san_upn:
            from utils.upn_san import build_upn_other_name
            for upn in san_upn:
                if upn and upn.strip():
                    san_list.append(build_upn_other_name(upn.strip()))

        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # Sign CSR
        hash_algo = HASH_ALGORITHMS.get(digest, hashes.SHA256())
        csr = builder.sign(private_key, hash_algo, default_backend())

        # Serialize
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return csr_pem, key_pem

    @staticmethod
    def sign_csr(
        csr_pem: bytes,
        ca_cert: x509.Certificate,
        ca_private_key,
        validity_days: int = 397,
        digest: str = 'sha256',
        cert_type: str = 'server_cert',
        cdp_url: str = None,
        cdp_urls: Optional[List[str]] = None,
        ocsp_url: str = None,
        ocsp_urls: Optional[List[str]] = None,
        aia_ca_issuers_url: str = None,
        aia_ca_issuers_urls: Optional[List[str]] = None,
        cps_uri: Optional[str] = None,
        cps_oid: Optional[str] = None,
        ocsp_must_staple: bool = False,
        extra_ekus: Optional[List[str]] = None,
        renewal_of=None,
        allow_sensitive_ekus: bool = False,
    ) -> bytes:
        """Sign a CSR with a CA. ``renewal_of``: existing certificate this
        signing renews — its names are graced by NameConstraints validation.
        ``allow_sensitive_ekus``: keep OCSPSigning/timeStamping from the CSR —
        reserved for the admin Sign-CSR path (an operator explicitly signing a
        delegated responder/TSA CSR); protocol enrollees never get them."""
        from utils.eku_validation import normalize_extra_ekus, to_object_identifiers, merge_eku_lists

        # Load CSR
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        if not csr.is_signature_valid:
            raise ValueError("CSR has invalid signature")

        # Key-strength floor. Enforced here rather than at each caller so every
        # issuance path (admin sign-CSR, ACME finalize, EST/SCEP, renewal)
        # inherits it from the one place that actually applies a CA signature.
        from utils.key_type import validate_enrollment_public_key
        key_err = validate_enrollment_public_key(csr.public_key())
        if key_err:
            raise ValueError(f"CSR public key rejected: {key_err}")

        # NameConstraints enforcement
        csr_sans = None
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            csr_sans = list(san_ext.value)
        except x509.ExtensionNotFound:
            pass
        ConstraintsMixin._validate_name_constraints(
            ca_cert, csr.subject, csr_sans, renewal_of=renewal_of
        )

        # If CSR has empty subject, populate CN from first SAN DNS name
        subject = csr.subject
        if not list(subject):
            try:
                san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name.value)])
                        break
            except x509.ExtensionNotFound:
                pass

        # Build certificate from CSR
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(cert_not_before())
        builder = builder.not_valid_after(
            utc_now() + timedelta(days=validity_days)
        )

        # Copy only extensions appropriate for the requested certificate role.
        # CA-only constraints from an enrollee CSR must never reach a leaf.
        issuing_ca = cert_type == 'intermediate_ca'
        try:
            csr_basic_constraints = csr.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
        except x509.ExtensionNotFound:
            csr_basic_constraints = None

        if (
            issuing_ca
            and csr_basic_constraints is not None
            and not csr_basic_constraints.value.ca
        ):
            raise ValueError(
                "Intermediate CA CSR BasicConstraints must set ca=True"
            )

        # Never copy SKI/AKI from the CSR — always derive them from the keys.
        skip_from_csr = {
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        }
        for extension in csr.extensions:
            if extension.oid in skip_from_csr:
                continue
            if not issuing_ca and extension.oid in _LEAF_CA_ONLY_EXTENSION_OIDS:
                continue
            if extension.oid == ExtensionOID.BASIC_CONSTRAINTS:
                if issuing_ca:
                    constraints = _capped_basic_constraints(
                        extension.value, ca_cert
                    )
                else:
                    constraints = x509.BasicConstraints(ca=False, path_length=None)
                builder = builder.add_extension(constraints, critical=True)
                continue
            if extension.oid == ExtensionOID.KEY_USAGE:
                usage = _key_usage_with_ca_signing(
                    extension.value, enabled=issuing_ca
                )
                builder = builder.add_extension(
                    usage,
                    critical=True if issuing_ca else extension.critical,
                )
                continue
            if extension.oid == ExtensionOID.EXTENDED_KEY_USAGE and not issuing_ca:
                safe_ekus, dropped_oids = _filter_csr_ekus(
                    extension.value, cert_type, allow_sensitive_ekus,
                    renewal_of=renewal_of,
                )
                if dropped_oids:
                    logger.warning(
                        "sign_csr: dropped EKU(s) %s from CSR — not permitted "
                        "for certificate type %r (the resolved certificate "
                        "type, not the CSR, decides leaf key purposes)",
                        [oid.dotted_string for oid in dropped_oids], cert_type,
                    )
                if safe_ekus:
                    builder = builder.add_extension(
                        x509.ExtendedKeyUsage(safe_ekus), extension.critical
                    )
                continue
            builder = builder.add_extension(extension.value, extension.critical)

        # Auto-add SAN from CN if CSR has no SAN extension
        try:
            csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            san_names = []
            for attr in subject:
                if attr.oid == NameOID.COMMON_NAME:
                    cn_val = attr.value
                    try:
                        ip = ipaddress.ip_address(cn_val)
                        san_names.append(x509.IPAddress(ip))
                    except ValueError:
                        if '@' in cn_val:
                            san_names.append(x509.RFC822Name(cn_val))
                        else:
                            san_names.append(x509.DNSName(cn_val))
                    break
            for attr in subject:
                if attr.oid == NameOID.EMAIL_ADDRESS:
                    email_val = attr.value
                    if not any(isinstance(n, x509.RFC822Name) and n.value == email_val for n in san_names):
                        san_names.append(x509.RFC822Name(email_val))
            if san_names:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_names),
                    critical=False,
                )

        # Add basic extensions if not in CSR
        try:
            csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound:
            if cert_type == 'intermediate_ca':
                # Route the default through the same clamp as a CSR-supplied
                # BasicConstraints: UCM's own generate_csr emits no
                # BasicConstraints at all, so without this the pathLen-0
                # refusal above never fired on the default API path (the
                # clamp itself is a no-op for any parent that may issue a
                # sub-CA, since the requested 0 is always within budget).
                builder = builder.add_extension(
                    _capped_basic_constraints(
                        x509.BasicConstraints(ca=True, path_length=0), ca_cert
                    ),
                    critical=True,
                )
            else:
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )

        # Add key usage based on cert type
        try:
            csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        except x509.ExtensionNotFound:
            if cert_type == 'intermediate_ca':
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True, key_encipherment=False,
                        content_commitment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=True, crl_sign=True,
                        encipher_only=False, decipher_only=False,
                    ),
                    critical=True,
                )
            elif cert_type == 'server_cert':
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True, key_encipherment=True,
                        content_commitment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=False, crl_sign=False,
                        encipher_only=False, decipher_only=False,
                    ),
                    critical=True,
                )

        # Add Extended Key Usage if not in CSR
        extra_oid_strs, extra_err = normalize_extra_ekus(extra_ekus)
        if extra_err:
            raise ValueError(f'Invalid extra_ekus: {extra_err}')
        extra_oids = to_object_identifiers(extra_oid_strs)

        try:
            existing_eku = csr.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            csr_has_eku = True
        except x509.ExtensionNotFound:
            existing_eku = None
            csr_has_eku = False

        if not csr_has_eku:
            base_eku = _default_ekus_for_cert_type(cert_type)
            merged = merge_eku_lists(base_eku, extra_oids)
            if merged:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(merged),
                    critical=False,
                )
        elif extra_oids:
            # Re-merging the CSR's original EKUs must not resurrect the
            # sensitive ones the copy loop above just dropped
            csr_ekus, _dropped = _filter_csr_ekus(
                existing_eku.value, cert_type, allow_sensitive_ekus,
                renewal_of=renewal_of,
            )
            merged = merge_eku_lists(csr_ekus, extra_oids)
            new_builder = x509.CertificateBuilder()
            new_builder = new_builder.subject_name(builder._subject_name)
            new_builder = new_builder.issuer_name(builder._issuer_name)
            new_builder = new_builder.public_key(builder._public_key)
            new_builder = new_builder.serial_number(builder._serial_number)
            new_builder = new_builder.not_valid_before(builder._not_valid_before)
            new_builder = new_builder.not_valid_after(builder._not_valid_after)
            for ext in builder._extensions:
                if ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                    continue
                new_builder = new_builder.add_extension(ext.value, ext.critical)
            new_builder = new_builder.add_extension(
                x509.ExtendedKeyUsage(merged), critical=existing_eku.critical
            )
            builder = new_builder

        # CRL Distribution Points
        all_cdp = cdp_urls or ([cdp_url] if cdp_url else [])
        if all_cdp:
            try:
                csr.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            except x509.ExtensionNotFound:
                dist_points = [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(url)],
                        relative_name=None, reasons=None, crl_issuer=None
                    )
                    for url in all_cdp
                ]
                builder = builder.add_extension(
                    x509.CRLDistributionPoints(dist_points),
                    critical=False
                )

        # Authority Information Access
        all_ocsp = ocsp_urls or ([ocsp_url] if ocsp_url else [])
        all_aia = aia_ca_issuers_urls or ([aia_ca_issuers_url] if aia_ca_issuers_url else [])
        aia_descriptions = []
        for uri in all_ocsp:
            aia_descriptions.append(
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(uri)
                )
            )
        for url in all_aia:
            aia_descriptions.append(
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(url)
                )
            )
        if aia_descriptions:
            try:
                csr.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            except x509.ExtensionNotFound:
                builder = builder.add_extension(
                    x509.AuthorityInformationAccess(aia_descriptions),
                    critical=False
                )

        # Certificate Policies
        if cps_uri:
            try:
                csr.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            except x509.ExtensionNotFound:
                policy_oid_obj = x509.ObjectIdentifier(cps_oid or '2.5.29.32.0')
                builder = builder.add_extension(
                    x509.CertificatePolicies([
                        x509.PolicyInformation(
                            policy_identifier=policy_oid_obj,
                            policy_qualifiers=[cps_uri]
                        )
                    ]),
                    critical=False
                )

        # SubjectKeyIdentifier — always from the CSR subject public key
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False
        )

        # AuthorityKeyIdentifier — always from the issuing CA's SKI
        builder = builder.add_extension(
            authority_key_identifier_from_issuer(ca_cert),
            critical=False
        )

        # OCSP Must-Staple
        if ocsp_must_staple:
            builder = builder.add_extension(
                x509.TLSFeature([x509.TLSFeatureType.status_request]),
                critical=False,
            )

        # Sign
        hash_algo = HASH_ALGORITHMS.get(digest, hashes.SHA256())
        certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hash_algo,
            backend=default_backend()
        )

        # Apply the Certificate Transparency policy (embed SCTs, enforce
        # ct_required) for leaf certs. This is the shared issuance path for
        # ACME finalize, EST and the API sign-CSR endpoint — previously only
        # the web create-certificate path honored CT, so ct_required silently
        # did nothing for ACME. Never applied to intermediate CAs.
        if not issuing_ca:
            from utils.ct_client import apply_ct_policy
            certificate, _ = apply_ct_policy(certificate, ca_cert, ca_private_key)

        return certificate.public_bytes(serialization.Encoding.PEM)
