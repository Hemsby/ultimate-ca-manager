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
