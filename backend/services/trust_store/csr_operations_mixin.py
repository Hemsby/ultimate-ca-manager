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

_MS_CERTIFICATE_TEMPLATE_OID = x509.ObjectIdentifier('1.3.6.1.4.1.311.21.7')


def _certificate_template_extension(template_oid, major=100, minor=0):
    """Build the Microsoft CertificateTemplateOID extension (MS-CRTD):
    ``SEQUENCE { templateID OBJECT IDENTIFIER, major INTEGER, minor
    INTEGER }``. ``cryptography`` has no native type for it, so it's
    hand-built with asn1crypto and wrapped as UnrecognizedExtension —
    same approach already used for CMC parsing in
    services/wstep/rst_parser.py. major/minor are arbitrary (Windows
    doesn't validate them against anything server-side); 100/0 mirrors
    a typical real ADCS template's default major version."""
    from asn1crypto import core as asn1_core

    class _TemplateVersion(asn1_core.Integer):
        pass

    class _CertificateTemplateOID(asn1_core.Sequence):
        _fields = [
            ('template_id', asn1_core.ObjectIdentifier),
            ('template_major_version', _TemplateVersion),
            ('template_minor_version', _TemplateVersion, {'optional': True}),
        ]

    der = _CertificateTemplateOID({
        'template_id': template_oid,
        'template_major_version': major,
        'template_minor_version': minor,
    }).dump()
    return x509.UnrecognizedExtension(_MS_CERTIFICATE_TEMPLATE_OID, der)


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


def _synthesize_san_from_subject(subject):
    """SAN entries implied by a subject's CN/email attributes -- same
    derivation ``sign_csr`` already applied when a CSR carries no SAN
    extension of its own. Factored out so this can be computed once and
    reused both for NameConstraints validation and for actually building the
    certificate's SAN extension, so the two can't drift apart (see
    ``sign_csr``'s ``override_subject`` handling)."""
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
    return san_names


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
        require_pop: bool = True,
        ms_certificate_template_oid: Optional[str] = None,
        override_subject: Optional[x509.Name] = None,
    ) -> bytes:
        """Sign a CSR with a CA. ``renewal_of``: existing certificate this
        signing renews — its names are graced by NameConstraints validation.
        ``allow_sensitive_ekus``: keep OCSPSigning/timeStamping from the CSR —
        reserved for the admin Sign-CSR path (an operator explicitly signing a
        delegated responder/TSA CSR); protocol enrollees never get them.
        ``require_pop=False`` skips the self-signature (proof-of-possession)
        check — only WSTEP passes this, for CSRs unwrapped from a PKCS#7/CMC
        envelope whose inner CertificationRequest isn't reliably self-signed
        by real Windows clients (see wstep_service._validate_csr, which
        makes the same exception for the same reason).
        ``ms_certificate_template_oid``: see the extension-building block
        below — only WSTEP passes this.
        ``override_subject``: replaces the CSR's own (possibly empty)
        subject before anything else happens with it — only WSTEP's Kerberos
        binding passes this, for the "naked" (no CN, no SAN) CSRs real
        Windows GPO machine autoenrollment submits for machine templates,
        trusting the CA to derive the subject from AD (see
        services/ad_connector/lookup.py). Computed before NameConstraints
        validation below, not after, so the constraint check sees the name
        that will actually land on the certificate rather than the raw
        CSR's own (empty) one — applying it later would let a CA's
        NameConstraints be silently bypassed by whatever subject was
        derived server-side."""
        from utils.eku_validation import normalize_extra_ekus, to_object_identifiers, merge_eku_lists

        # Load CSR
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        if require_pop and not csr.is_signature_valid:
            raise ValueError("CSR has invalid signature")

        # Effective subject: an override (if any) wins outright; otherwise
        # fall back to populating CN from the CSR's own first SAN DNS name
        # if the CSR's subject is empty.
        subject = override_subject if override_subject is not None else csr.subject
        if not list(subject):
            try:
                san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name.value)])
                        break
            except x509.ExtensionNotFound:
                pass

        # Effective SAN for constraint-checking: the CSR's own SAN extension
        # if it has one, else whatever will be auto-synthesized from the
        # (possibly overridden) subject below -- NameConstraints must see
        # the name that will actually land on the certificate, not an empty
        # list just because the CSR itself omitted SAN.
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            csr_sans = list(san_ext.value)
            has_csr_san = True
        except x509.ExtensionNotFound:
            csr_sans = None
            has_csr_san = False

        effective_sans = csr_sans if has_csr_san else _synthesize_san_from_subject(subject)

        ConstraintsMixin._validate_name_constraints(
            ca_cert, subject, effective_sans if effective_sans else None, renewal_of=renewal_of
        )

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
                constraints = (
                    extension.value
                    if issuing_ca
                    else x509.BasicConstraints(ca=False, path_length=None)
                )
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
                if allow_sensitive_ekus:
                    safe_ekus = list(extension.value)
                else:
                    safe_ekus = [
                        oid for oid in extension.value
                        if oid not in _LEAF_FORBIDDEN_EKU_OIDS
                    ]
                    dropped = [
                        oid.dotted_string for oid in extension.value
                        if oid in _LEAF_FORBIDDEN_EKU_OIDS
                    ]
                    if dropped:
                        logger.warning(
                            "sign_csr: dropped sensitive EKU(s) %s from CSR "
                            "(protocol enrollees may not request delegated "
                            "OCSP/timestamping authority)", dropped,
                        )
                if safe_ekus:
                    builder = builder.add_extension(
                        x509.ExtendedKeyUsage(safe_ekus), extension.critical
                    )
                continue
            builder = builder.add_extension(extension.value, extension.critical)

        # Auto-add SAN from CN if the CSR had no SAN extension -- reuses
        # effective_sans, already computed above for NameConstraints, so
        # what got constraint-checked and what actually lands on the
        # certificate can't drift apart.
        if not has_csr_san and effective_sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(effective_sans),
                critical=False,
            )

        # Add basic extensions if not in CSR
        try:
            csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound:
            if cert_type == 'intermediate_ca':
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=True, path_length=0),
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
            base_eku = []
            if cert_type == 'server_cert':
                base_eku = [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
            elif cert_type in ('usr_cert', 'client_cert'):
                base_eku = [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            elif cert_type in ('combined_server_client', 'combined_cert'):
                base_eku = [
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            merged = merge_eku_lists(base_eku, extra_oids)
            if merged:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(merged),
                    critical=False,
                )
        elif extra_oids:
            # Re-merging the CSR's original EKUs must not resurrect the
            # sensitive ones the copy loop above just dropped
            csr_ekus = list(existing_eku.value)
            if not allow_sensitive_ekus:
                csr_ekus = [
                    oid for oid in csr_ekus
                    if oid not in _LEAF_FORBIDDEN_EKU_OIDS
                ]
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

        # Microsoft Certificate Template extension (szOID_CERTIFICATE_TEMPLATE,
        # 1.3.6.1.4.1.311.21.7) — only WSTEP passes this. Real Windows clients
        # read this back off the issued cert to confirm it matches the policy
        # they selected via XCEP; a cert with no template property at all was
        # observed failing CX509Enrollment::Enroll with CERTSRV_E_PROPERTY_EMPTY
        # ("the requested property value is empty") during real-client interop
        # testing. `cryptography` has no built-in type for this MS-CRTD
        # extension, so it's hand-built and added as UnrecognizedExtension.
        if ms_certificate_template_oid:
            builder = builder.add_extension(
                _certificate_template_extension(ms_certificate_template_oid),
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
