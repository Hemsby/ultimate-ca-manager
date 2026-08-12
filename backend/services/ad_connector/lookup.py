"""
LDAP client for the Active Directory Connector.

Two things live here:

1. Kerberos principal parsing (``parse_kerberos_principal``, ``is_machine_principal``)
   -- a real Kerberos machine account principal from ``services/kerberos/
   negotiate_auth.py`` looks like ``WIN11$@HAGLAND.DOMAIN`` (confirmed
   against the lab); the trailing ``$`` on the pre-@ part is how AD marks a
   computer account's sAMAccountName, and is the only signal available to
   tell "this is a machine" apart from "this is a user" -- there is no
   template selector anywhere in MS-WSTEP's wire protocol to key off instead
   (see wstep_service.py's ``_match_template`` docstring).

2. The actual AD lookups (``lookup_computer_dns_hostname``,
   ``lookup_user_ad_identity``) MS-WSTEP's Kerberos issuance path uses to
   resolve a naked (subject-less) CSR's identity: real Windows unattended
   GPO autoenrollment intentionally submits a CSR with no CN/SAN for
   templates configured to build the subject from Active Directory,
   trusting the CA to derive it server-side -- ``CN=<computer's AD
   dnsHostName>`` for a machine account, or the user object's own
   directory-path DN plus its ``userPrincipalName`` as a SAN OtherName for
   a person account -- exactly what real ADCS does from the requester's AD
   object. UCM has no other source for that identity, hence this connector.

Bind/search mechanics mirror ``api/v2/sso/connection_tests.py``'s
``_ldap_authenticate_user``/``api/v2/sso/helpers.py``'s ``_build_ldap_tls``
(same ``ldap3`` conventions), but operate on this module's own
``ADConnectorConfig`` singleton -- not ``SSOProvider`` -- and fix a leaked
temp CA-bundle file that exists in that code (no matching cleanup there).

Every public lookup function here fails closed to ``None``/a structured
failure result, never an exception: a broken AD Connector must degrade to
"can't derive a subject" (the pre-existing naked-CSR rejection), not a 500.
"""
import logging
import os
import ssl
import tempfile

logger = logging.getLogger(__name__)


def parse_kerberos_principal(principal):
    """``'WIN11$@HAGLAND.DOMAIN'`` -> ``('WIN11$', 'HAGLAND.DOMAIN')``.

    ``None`` for anything that isn't exactly one non-empty local-part and
    one non-empty realm separated by ``@``.
    """
    if not principal or '@' not in principal:
        return None
    local, _, realm = principal.partition('@')
    if not local or not realm:
        return None
    return local, realm


def _realm_from_base_dn(base_dn):
    """``'DC=hagland,DC=domain'`` -> ``'HAGLAND.DOMAIN'`` -- the standard AD
    convention of domain DNS name == Kerberos realm (upper-cased). ``None``
    if the DN has no DC components at all (malformed base_dn)."""
    from ldap3.utils.dn import parse_dn

    try:
        components = parse_dn(base_dn)
    except Exception:
        return None
    dc_values = [value for attr, value, _sep in components if attr.upper() == 'DC']
    if not dc_values:
        return None
    return '.'.join(dc_values).upper()


def realm_matches_connector(realm):
    """Whether ``realm`` (from an authenticated Kerberos principal, e.g.
    ``'HAGLAND.DOMAIN'``) matches the domain this AD Connector is configured
    against, so a caller can refuse to map a principal from an unexpected
    realm to a same-named ``sAMAccountName`` in *this* domain -- Kerberos
    cross-realm trust means a client_principal's realm isn't necessarily the
    domain UCM's AD Connector actually points at, and ``sAMAccountName``
    alone (what ``parse_kerberos_principal`` splits it into) is not globally
    unique the way a realm-qualified principal is.

    False (fail closed) if the connector isn't configured/enabled, its
    base_dn doesn't parse to a realm, or ``realm`` is empty -- callers must
    treat that identically to "lookup not possible", not "skip the check".
    Never raises.
    """
    if not realm:
        return False
    from models import ADConnectorConfig

    config = ADConnectorConfig.get_singleton()
    if not config or not config.enabled or not config.base_dn:
        return False
    connector_realm = _realm_from_base_dn(config.base_dn)
    return bool(connector_realm) and connector_realm == realm.upper()


def is_machine_principal(principal):
    """Whether a Kerberos principal looks like a computer account.

    Never raises -- malformed input (no ``@``, empty string) is just not a
    machine principal, not an error.
    """
    if not principal or '@' not in principal:
        return False
    return principal.split('@', 1)[0].endswith('$')


def _build_tls(config):
    """``ldap3.Tls`` from a config-like object's ``use_ssl``/``verify_ssl``/
    ``ca_bundle``. Returns ``(tls, cleanup)`` -- ``cleanup()`` must always be
    called once the connection using it is done, to remove any temp
    CA-bundle file this created.
    """
    import ldap3

    verify_ssl = config.verify_ssl if config.verify_ssl is not None else True
    ca_path = None

    def cleanup():
        if ca_path:
            try:
                os.unlink(ca_path)
            except OSError:
                pass

    if not config.use_ssl and not verify_ssl:
        return None, cleanup
    if not verify_ssl:
        return ldap3.Tls(validate=ssl.CERT_NONE), cleanup

    ca_bundle = getattr(config, 'ca_bundle', None)
    if ca_bundle:
        fd, ca_path = tempfile.mkstemp(suffix='.pem', prefix='ucm_ad_connector_ca_')
        try:
            os.write(fd, ca_bundle.encode('utf-8') if isinstance(ca_bundle, str) else ca_bundle)
        finally:
            os.close(fd)
        return ldap3.Tls(ca_certs_file=ca_path, validate=ssl.CERT_REQUIRED), cleanup

    # Verify requested, no explicit bundle: validate against the system
    # trust store rather than leaving ldap3 on its unvalidated default.
    return ldap3.Tls(validate=ssl.CERT_REQUIRED), cleanup


# Every lookup here runs synchronously inside a WSTEP/XCEP request handler
# (gevent-cooperative, but still blocking that greenlet) -- a black-holed
# or firewall-dropped DC with no timeout would stall the enrollment request
# indefinitely instead of failing closed like every other error mode here.
_LDAP_CONNECT_TIMEOUT_SECONDS = 10
_LDAP_RECEIVE_TIMEOUT_SECONDS = 10


def _connect(config):
    """Bind as the connector's service account. Returns an open, bound
    ``ldap3.Connection``. Raises on any failure -- callers translate that
    into their own fail-safe behavior."""
    import ldap3

    tls, cleanup = _build_tls(config)
    try:
        server = ldap3.Server(
            config.server, port=config.port, use_ssl=config.use_ssl,
            tls=tls, get_info=ldap3.ALL, connect_timeout=_LDAP_CONNECT_TIMEOUT_SECONDS,
        )
        return ldap3.Connection(
            server, user=config.bind_dn, password=config.bind_password,
            auto_bind=True, check_names=False, receive_timeout=_LDAP_RECEIVE_TIMEOUT_SECONDS,
        )
    finally:
        # auto_bind=True performs the TLS handshake synchronously above, so
        # the temp CA file (if any) is no longer needed once this returns.
        cleanup()


def lookup_computer_dns_hostname(sam_account_name):
    """The AD computer object's ``dNSHostName`` for ``sam_account_name``
    (e.g. ``'WIN11$'``, trailing ``$`` included -- it's a real part of the
    attribute value, not an LDAP filter metacharacter to strip).

    Returns ``None`` on every failure mode: connector not configured or
    disabled, unreachable, bind failure, entry not found, or the attribute
    is empty/missing. Never raises.
    """
    from ldap3.utils.conv import escape_filter_chars

    from models import ADConnectorConfig

    config = ADConnectorConfig.get_singleton()
    if not config or not config.enabled or not config.server or not config.base_dn:
        return None

    try:
        conn = _connect(config)
    except Exception as e:
        logger.warning("AD Connector: bind failed during computer lookup: %s", e)
        return None

    try:
        safe_sam = escape_filter_chars(sam_account_name)
        conn.search(
            config.base_dn,
            f'(&(objectClass=computer)(sAMAccountName={safe_sam}))',
            attributes=['dNSHostName'],
        )
        if not conn.entries:
            return None
        entry = conn.entries[0]
        if 'dNSHostName' not in entry or not entry.dNSHostName.value:
            return None
        return str(entry.dNSHostName.value)
    except Exception as e:
        logger.warning("AD Connector: computer lookup failed: %s", e)
        return None
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _sid_bytes_to_string(raw):
    """Windows binary SID -> ``"S-1-5-21-...-<RID>"`` string form.

    Layout: ``byte[0]`` revision, ``byte[1]`` sub-authority count,
    ``bytes[2:8]`` big-endian identifier authority, then N x 4-byte
    little-endian sub-authorities. Verified against a real captured SID
    (both a live LDAP query for a lab machine account and the SID string
    embedded in a real ADCS-issued certificate's security extension agree
    on the domain-SID prefix) -- not spec-derived.

    ``None`` on any malformed input (wrong length for the declared
    sub-authority count, empty bytes) rather than raising -- this is
    untrusted binary data straight from a directory attribute.
    """
    if not raw or len(raw) < 8:
        return None
    revision = raw[0]
    sub_count = raw[1]
    expected_len = 8 + sub_count * 4
    if len(raw) != expected_len:
        return None
    authority = int.from_bytes(raw[2:8], 'big')
    sub_authorities = [
        int.from_bytes(raw[8 + i * 4:12 + i * 4], 'little')
        for i in range(sub_count)
    ]
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in sub_authorities)


def lookup_object_sid(sam_account_name):
    """The AD object's ``objectSid`` (user or computer -- no ``objectClass``
    filter needed since ``sAMAccountName`` is domain-unique, machine
    accounts keep their trailing ``$``), as a ``"S-1-5-21-..."`` string --
    the exact form real ADCS embeds in the SID security extension
    (``szOID_NTDS_CA_SECURITY_EXT``, see services/trust_store/
    csr_operations_mixin.py's ``_ad_security_extension``) for KB5014754
    strong certificate mapping.

    ``ldap3`` does not auto-format ``objectSid`` -- ``entry.objectSid.value``
    returns the raw bytes mis-decoded as a string, so this reads
    ``raw_values[0]`` (the real binary SID) and converts it via
    ``_sid_bytes_to_string``.

    Returns ``None`` on every failure mode: connector not configured or
    disabled, unreachable, bind failure, entry not found, or the attribute
    is empty/malformed. Never raises. Callers needing to distinguish
    "connector not configured" (skip this feature) from "configured but
    this lookup failed" (deny, for strong mapping) must check
    ``ADConnectorConfig`` themselves before calling this -- this function's
    ``None`` return does not carry that distinction, matching every other
    lookup in this module.
    """
    from ldap3.utils.conv import escape_filter_chars

    from models import ADConnectorConfig

    config = ADConnectorConfig.get_singleton()
    if not config or not config.enabled or not config.server or not config.base_dn:
        return None

    try:
        conn = _connect(config)
    except Exception as e:
        logger.warning("AD Connector: bind failed during SID lookup: %s", e)
        return None

    try:
        safe_sam = escape_filter_chars(sam_account_name)
        conn.search(
            config.base_dn,
            f'(sAMAccountName={safe_sam})',
            attributes=['objectSid'],
        )
        if not conn.entries:
            return None
        entry = conn.entries[0]
        if 'objectSid' not in entry or not entry.objectSid.raw_values:
            return None
        return _sid_bytes_to_string(entry.objectSid.raw_values[0])
    except Exception as e:
        logger.warning("AD Connector: SID lookup failed: %s", e)
        return None
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def lookup_user_ad_identity(sam_account_name):
    """The AD user object's directory path (as ordered RDN components, for
    building an x509.Name matching real ADCS's directory-path subject),
    userPrincipalName, and mail (if set), for ``sam_account_name`` (no
    trailing ``$`` -- a real person account, not a computer -- see
    ``is_machine_principal``).

    Returns ``{'dn_components': [(attr, value), ...], 'upn': str, 'mail':
    str | None}`` -- the DN components ordered exactly as AD returns them
    (leaf to root, e.g. ``[('CN', 'Roy Hagland'), ('CN', 'Users'), ('DC',
    'hagland'), ('DC', 'domain')]``), confirmed against a real ADCS-issued
    User certificate's subject in the lab. ``None`` on every failure mode
    -- connector not configured/disabled, unreachable, bind failure, entry
    not found, or no ``userPrincipalName`` set. Never raises.

    ``mail`` is deliberately optional (``None`` when unset), not a failure
    mode: real ADCS's own CT_FLAG_SUBJECT_REQUIRE_EMAIL hard-declines
    autoenrollment outright for any user with no ``mail`` attribute, which
    would make a single template unusable for a mixed user base. Callers
    include the email in the issued cert's subject/SAN when present and
    simply omit it otherwise, rather than advertising it as a policy-level
    requirement (see wstep_service.py's issue()).
    """
    from ldap3.utils.conv import escape_filter_chars
    from ldap3.utils.dn import parse_dn

    from models import ADConnectorConfig

    config = ADConnectorConfig.get_singleton()
    if not config or not config.enabled or not config.server or not config.base_dn:
        return None

    try:
        conn = _connect(config)
    except Exception as e:
        logger.warning("AD Connector: bind failed during user lookup: %s", e)
        return None

    try:
        safe_sam = escape_filter_chars(sam_account_name)
        conn.search(
            config.base_dn,
            f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_sam}))',
            attributes=['userPrincipalName', 'mail'],
        )
        if not conn.entries:
            return None
        entry = conn.entries[0]
        if 'userPrincipalName' not in entry or not entry.userPrincipalName.value:
            return None
        upn = str(entry.userPrincipalName.value)
        mail = str(entry.mail.value) if 'mail' in entry and entry.mail.value else None
        dn_components = [(attr, value) for attr, value, _sep in parse_dn(entry.entry_dn)]
        if not dn_components:
            return None
        return {'dn_components': dn_components, 'upn': upn, 'mail': mail}
    except Exception as e:
        logger.warning("AD Connector: user identity lookup failed: %s", e)
        return None
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _looks_like_dn(value):
    """Cheap DN heuristic (``'CN=Foo,OU=Groups,DC=hagland,DC=domain'``) vs a
    plain name (``'Foo'``, ``'VPN-Enroll'``) -- good enough to route
    ``is_member_of_group``'s group argument without requiring admins to
    always type a full DN. A false negative just means an extra lookup, not
    a security problem: the group is still resolved by name search below.
    """
    return '=' in value and ',' in value


def is_member_of_group(sam_account_name, group):
    """Whether the AD account ``sam_account_name`` (no trailing ``$``
    stripped -- caller passes it exactly as parsed from the Kerberos
    principal, so a machine account keeps its ``$``) is a member of
    ``group``, given either as a full DN or a plain name (``sAMAccountName``
    or ``cn``) -- resolved to a DN first via search if it doesn't already
    look like one (see ``_looks_like_dn``).

    Uses AD's ``LDAP_MATCHING_RULE_IN_CHAIN`` (``:1.2.840.113556.1.4.1941:``)
    on ``memberOf`` so nested group membership counts, matching how a real
    ADCS Enroll ACL evaluates a principal's full token group list rather
    than only direct membership.

    Fails closed to ``False`` on every failure mode -- connector not
    configured/disabled, unreachable, bind failure, group not found, or
    account not found/not a member. Never raises. Callers must treat
    ``False`` as "deny", not "skip the check" -- this is a security gate,
    unlike the subject-derivation lookups above which fail closed to a
    softer "can't derive a subject, fall through to normal rejection".
    """
    from ldap3.utils.conv import escape_filter_chars

    from models import ADConnectorConfig

    if not sam_account_name or not group:
        return False

    config = ADConnectorConfig.get_singleton()
    if not config or not config.enabled or not config.server or not config.base_dn:
        return False

    try:
        conn = _connect(config)
    except Exception as e:
        logger.warning("AD Connector: bind failed during group membership check: %s", e)
        return False

    try:
        if _looks_like_dn(group):
            group_dn = group
        else:
            safe_group = escape_filter_chars(group)
            conn.search(
                config.base_dn,
                f'(&(objectClass=group)(|(sAMAccountName={safe_group})(cn={safe_group})))',
                attributes=['distinguishedName'],
            )
            if not conn.entries:
                logger.warning("AD Connector: group %r not found for Enroll ACL check", group)
                return False
            group_dn = conn.entries[0].entry_dn

        safe_sam = escape_filter_chars(sam_account_name)
        safe_group_dn = escape_filter_chars(group_dn)
        conn.search(
            config.base_dn,
            f'(&(sAMAccountName={safe_sam})'
            f'(memberOf:1.2.840.113556.1.4.1941:={safe_group_dn}))',
            attributes=['sAMAccountName'],
        )
        return bool(conn.entries)
    except Exception as e:
        logger.warning("AD Connector: group membership check failed: %s", e)
        return False
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def test_connection(config):
    """Test connectivity + bind for a config-like object -- either the
    saved ``ADConnectorConfig`` row or an unsaved ``SimpleNamespace`` built
    from a settings form (mirrors ``MicrosoftCAConnectionMixin``'s
    inline-vs-saved test pattern). Returns ``{'success': bool, 'message': str}``,
    never raises.
    """
    if not config.server:
        return {'success': False, 'message': 'Server is required'}
    try:
        conn = _connect(config)
    except Exception as e:
        return {'success': False, 'message': f'Connection failed: {e}'}
    try:
        conn.unbind()
    except Exception:
        pass
    return {'success': True, 'message': 'Connected and bound successfully'}
