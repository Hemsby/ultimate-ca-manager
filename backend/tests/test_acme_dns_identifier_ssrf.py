"""Regression tests: ACME challenge SSRF follow-ups to PR #244.

Three holes survived that fix.

1. A ``dns`` identifier was never syntax-checked, so a value carrying a port or
   userinfo ('169.254.169.254:80', 'evil@10.0.0.5') was accepted by new-order.
   Such a value is unresolvable as a HOSTNAME, so ``validate_host_not_private``
   swallowed the resolver error and returned — fail-open — and ``requests`` then
   re-parsed it as a URL *authority*, split off the port/userinfo and connected
   to the private address behind it.

2. The private-address guard only runs when ``acme.allow_private_ips`` is off,
   and it defaults to ON (on-prem issuance is the main use case). So in the
   default configuration an order for 169.254.169.254 still produced a
   challenge GET to the cloud metadata service, even though everywhere else in
   UCM (``validate_url_not_cloud_metadata``) metadata stays blocked while
   RFC 1918 ranges are allowed.

3. The guard resolved the identifier and ``requests`` resolved it again: a
   short-TTL record can answer public for the check and private for the fetch.

The validators are driven through a minimal harness rather than the ``app``
fixture — these are function-level tests of the mixin and need no database.
Every DNS answer is stubbed: the runner's resolver (an NXDOMAIN-hijacking ISP
resolver, say) must never decide the outcome.
"""
import socket

import pytest

import utils.ssrf_protection as ssrf_protection
from services.acme.mixins import challenge as challenge_mod
from services.acme.mixins.challenge import ChallengeMixin


# Values that are NOT resolvable as a hostname but ARE reachable once an HTTP
# client parses them as a URL authority. All five returned without raising
# before the guard was made to fail closed.
UNRESOLVABLE_BUT_REACHABLE = [
    '169.254.169.254:80',
    'evil@169.254.169.254',
    '127.0.0.1:8080',
    '169.254.169.254.',
    '169.254.169.254/latest/meta-data/#',
]


# --------------------------------------------------------------------------
# Harness — the collaborators the two validators actually touch
# --------------------------------------------------------------------------

class _StubSession:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass


class _StubDb:
    def __init__(self):
        self.session = _StubSession()


class _Auth:
    def __init__(self, identifier_type, identifier_value):
        self.identifier_type = identifier_type
        self.identifier_value = identifier_value
        self.status = 'pending'
        self.order = None
        self.challenges = []


class _Challenge:
    def __init__(self, auth, token='ssrf-probe-token'):
        self.authorization = auth
        self.token = token
        self.status = 'pending'
        self.error = None
        self.validated = None
        auth.challenges.append(self)


class _Account:
    jwk_thumbprint = 'test-thumbprint'


class _Service(ChallengeMixin):
    def __init__(self, allow_private_ips):
        self._allow_private_ips = allow_private_ips

    def _acme_allow_private_ips(self):
        return self._allow_private_ips

    def _compute_key_authorization(self, token, jwk_thumbprint):
        return f'{token}.{jwk_thumbprint}'


def _drive(validator_name, identifier_type, value, allow_private_ips):
    """Run one challenge validator against a fresh challenge. Returns
    (result, challenge)."""
    auth = _Auth(identifier_type, value)
    challenge = _Challenge(auth)
    service = _Service(allow_private_ips)
    result = getattr(service, validator_name)(challenge, _Account())
    return result, challenge


def _assert_rejected(result, challenge, outbound):
    """A blocked challenge: no outbound attempt, and the ACME state actually
    says rejectedIdentifier (not merely 'returned False')."""
    assert result is False
    assert not outbound['fetched'], (
        f"the validator reached out to {outbound['target']!r}"
    )
    assert challenge.status == 'invalid'
    assert 'rejectedIdentifier' in (challenge.error or '')
    assert challenge.authorization.status == 'invalid'


@pytest.fixture
def outbound(monkeypatch):
    """Record — and refuse — every outbound attempt a validator makes."""
    import requests

    seen = {'fetched': False, 'target': None, 'pinned': None}

    def _get(url, *_a, **_kw):
        seen['fetched'] = True
        seen['target'] = url
        seen['pinned'] = dict(
            getattr(ssrf_protection._pinned_resolution, 'host_to_ip', None) or {}
        )
        raise AssertionError(f'SSRF: outbound HTTP attempted to {url!r}')

    def _connect(address, *_a, **_kw):
        seen['fetched'] = True
        seen['target'] = address
        raise AssertionError(f'SSRF: outbound connection attempted to {address!r}')

    monkeypatch.setattr(requests, 'get', _get)
    monkeypatch.setattr(socket, 'create_connection', _connect)
    monkeypatch.setattr(challenge_mod, 'db', _StubDb())
    return seen


@pytest.fixture
def no_dns(monkeypatch):
    """Every name is unresolvable."""
    def _fail(host, *_a, **_kw):
        raise socket.gaierror(-2, 'Name or service not known')

    monkeypatch.setattr(ssrf_protection.socket, 'getaddrinfo', _fail)


@pytest.fixture
def dns_public(monkeypatch):
    """Every name resolves to one public address."""
    def _public(host, *_a, **_kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]

    monkeypatch.setattr(ssrf_protection.socket, 'getaddrinfo', _public)


# --------------------------------------------------------------------------
# 1. The guard fails closed on a host it can neither parse nor resolve
# --------------------------------------------------------------------------

@pytest.mark.parametrize('value', UNRESOLVABLE_BUT_REACHABLE)
def test_guard_fails_closed_on_unresolvable_host(value, no_dns):
    with pytest.raises(ValueError):
        ssrf_protection.validate_host_not_private(value)


def test_guard_returns_the_validated_ip_for_pinning(dns_public):
    assert ssrf_protection.validate_host_not_private('example.test') == '93.184.216.34'
    assert ssrf_protection.validate_host_not_private('8.8.8.8') == '8.8.8.8'


# --------------------------------------------------------------------------
# 2. new-order / new-authz refuse a DNS identifier that is not a domain name
# --------------------------------------------------------------------------

@pytest.mark.parametrize('value', [
    # '169.254.169.254.' is deliberately absent: it IS a syntactically valid
    # domain name, so it is the guard's job (below), not the parser's.
    '169.254.169.254:80',
    'evil@169.254.169.254',
    '127.0.0.1:8080',
    '169.254.169.254/latest/meta-data/#',
    'host with space.example.com',
    'http://example.com',
    'example.com:443',
    '',
    'x' * 250 + '.example.com',
    '-leading-hyphen.example.com',
    'a..example.com',
    None,
])
def test_malformed_dns_identifier_is_rejected(value):
    from api.acme.acme_api import validate_acme_identifier
    ok, err_type, detail = validate_acme_identifier({'type': 'dns', 'value': value})
    assert ok is False
    assert err_type == 'malformed'
    assert detail


@pytest.mark.parametrize('value', [
    'example.com',
    '*.example.com',
    'sub.example.co.uk',
    'xn--80ak6aa92e.com',      # punycode / IDN A-label
    'host-1.internal.lan',
    'EXAMPLE.com',
    'example.com.',            # single trailing root dot
    '_acme-challenge.example.com',
    'localhost',
])
def test_legitimate_dns_identifier_is_accepted(value):
    from api.acme.acme_api import validate_acme_identifier
    ok, err_type, _ = validate_acme_identifier({'type': 'dns', 'value': value})
    assert ok is True
    assert err_type is None


# --------------------------------------------------------------------------
# 3. End to end: the validators refuse the bypass values
# --------------------------------------------------------------------------

@pytest.mark.parametrize('value', [
    '10.0.0.5:8080',            # port — not metadata, so only the guard can stop it
    'evil@10.0.0.5',            # userinfo
    '169.254.169.254:80',
])
def test_http01_blocks_a_dns_identifier_carrying_a_port_or_userinfo(
    value, outbound, no_dns
):
    result, challenge = _drive(
        'validate_http01_challenge', 'dns', value, allow_private_ips=False
    )
    _assert_rejected(result, challenge, outbound)


# --------------------------------------------------------------------------
# 4. Cloud metadata is refused even when private IPs are allowed (the default)
# --------------------------------------------------------------------------

@pytest.mark.parametrize('identifier_type,value', [
    ('ip', '169.254.169.254'),          # AWS/Azure/GCP IMDS
    ('ip', '100.100.100.200'),          # Alibaba Cloud
    ('ip', 'fd00:ec2::254'),            # AWS IPv6 — bracketed into the URL
    ('dns', 'metadata.google.internal'),
    ('dns', '169.254.169.254.'),        # IP dressed up as a domain name
])
def test_http01_blocks_metadata_with_private_ips_allowed(
    identifier_type, value, outbound, no_dns
):
    result, challenge = _drive(
        'validate_http01_challenge', identifier_type, value,
        allow_private_ips=True,
    )
    _assert_rejected(result, challenge, outbound)


@pytest.mark.parametrize('identifier_type,value', [
    ('ip', '169.254.169.254'),
    ('dns', 'metadata.google.internal'),
])
def test_tls_alpn01_blocks_metadata_with_private_ips_allowed(
    identifier_type, value, outbound, no_dns
):
    result, challenge = _drive(
        'validate_tls_alpn01_challenge', identifier_type, value,
        allow_private_ips=True,
    )
    _assert_rejected(result, challenge, outbound)


@pytest.mark.parametrize('identifier_type,value', [
    ('ip', '10.0.0.5'),          # RFC 1918 — the on-prem use case
    ('ip', '192.168.1.10'),
    ('ip', '127.0.0.1'),         # colocated client
    ('dns', 'printer.internal.lan'),
])
def test_private_targets_still_work_when_allowed(
    identifier_type, value, outbound, no_dns
):
    """Control: the metadata check must not tighten the default configuration
    beyond metadata itself, or every LAN deployment breaks."""
    result, challenge = _drive(
        'validate_http01_challenge', identifier_type, value,
        allow_private_ips=True,
    )
    assert result is False           # the stubbed fetch raises
    assert outbound['fetched'], 'a legitimate private target was blocked'
    assert 'rejectedIdentifier' not in (challenge.error or '')


# --------------------------------------------------------------------------
# 5. DNS rebinding: the fetch is pinned to the address that was validated
# --------------------------------------------------------------------------

def test_http01_pins_the_fetch_to_the_validated_address(outbound, dns_public):
    result, _challenge = _drive(
        'validate_http01_challenge', 'dns', 'rebind.example.test',
        allow_private_ips=False,
    )
    assert result is False           # the stubbed fetch raises
    assert outbound['fetched']
    assert outbound['pinned'].get('rebind.example.test') == '93.184.216.34', (
        'the challenge fetch was not pinned to the validated address — a '
        'second DNS answer can still redirect it'
    )


def test_pinned_connection_ignores_a_second_dns_answer(monkeypatch):
    """The pin overrides whatever address the connection lookup would use."""
    ssrf_protection._ensure_urllib3_patched()
    seen = {}
    monkeypatch.setattr(
        ssrf_protection, '_orig_create_connection',
        lambda address, *_a, **_kw: seen.setdefault('address', address),
    )
    with ssrf_protection.pin_host('rebind.example.test', '93.184.216.34'):
        ssrf_protection._patched_create_connection(('rebind.example.test', 80))
    assert seen['address'] == ('93.184.216.34', 80)
