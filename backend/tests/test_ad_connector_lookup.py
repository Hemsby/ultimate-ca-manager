"""
Tests for services/ad_connector/lookup.py:

- parse_kerberos_principal / is_machine_principal: pure string parsing,
  no I/O.
- lookup_computer_dns_hostname: every failure mode (not configured, bind
  failure, not found, empty attribute) must return None, never raise --
  the WSTEP naked-CSR fallback depends on that to fail safely closed
  (falling back to the existing rejection, never issuing something wrong).
"""
import pytest

from models import db, ADConnectorConfig
from services.ad_connector import lookup


class TestParseKerberosPrincipal:
    def test_machine_principal(self):
        assert lookup.parse_kerberos_principal('WIN11$@HAGLAND.DOMAIN') == ('WIN11$', 'HAGLAND.DOMAIN')

    def test_user_principal(self):
        assert lookup.parse_kerberos_principal('alice@HAGLAND.DOMAIN') == ('alice', 'HAGLAND.DOMAIN')

    def test_no_at_sign(self):
        assert lookup.parse_kerberos_principal('WIN11$') is None

    def test_empty_local_part(self):
        assert lookup.parse_kerberos_principal('@HAGLAND.DOMAIN') is None

    def test_empty_realm(self):
        assert lookup.parse_kerberos_principal('WIN11$@') is None

    def test_empty_string(self):
        assert lookup.parse_kerberos_principal('') is None

    def test_none(self):
        assert lookup.parse_kerberos_principal(None) is None


class TestIsMachinePrincipal:
    def test_machine_principal(self):
        assert lookup.is_machine_principal('WIN11$@HAGLAND.DOMAIN') is True

    def test_user_principal(self):
        assert lookup.is_machine_principal('alice@HAGLAND.DOMAIN') is False

    def test_malformed_no_at(self):
        assert lookup.is_machine_principal('WIN11$') is False

    def test_empty_string(self):
        assert lookup.is_machine_principal('') is False

    def test_none(self):
        assert lookup.is_machine_principal(None) is False


class TestRealmMatchesConnector:
    def test_matches(self, app, monkeypatch):
        _configure(monkeypatch, app)
        with app.app_context():
            assert lookup.realm_matches_connector('HAGLAND.DOMAIN') is True

    def test_case_insensitive(self, app, monkeypatch):
        _configure(monkeypatch, app)
        with app.app_context():
            assert lookup.realm_matches_connector('hagland.domain') is True

    def test_different_realm_rejected(self, app, monkeypatch):
        """A ticket from a trusted-but-different realm must not be treated
        as though it named an account in *this* domain -- sAMAccountName
        alone isn't globally unique the way a realm-qualified principal
        is."""
        _configure(monkeypatch, app)
        with app.app_context():
            assert lookup.realm_matches_connector('OTHER.DOMAIN') is False

    def test_connector_not_configured(self, app):
        with app.app_context():
            ADConnectorConfig.query.delete()
            db.session.commit()
            assert lookup.realm_matches_connector('HAGLAND.DOMAIN') is False

    def test_connector_disabled(self, app, monkeypatch):
        _configure(monkeypatch, app, enabled=False)
        with app.app_context():
            assert lookup.realm_matches_connector('HAGLAND.DOMAIN') is False

    def test_empty_realm(self, app, monkeypatch):
        _configure(monkeypatch, app)
        with app.app_context():
            assert lookup.realm_matches_connector('') is False
            assert lookup.realm_matches_connector(None) is False

    def test_malformed_base_dn_fails_closed(self, app):
        with app.app_context():
            ADConnectorConfig.query.delete()
            config = ADConnectorConfig(
                server='dc1.hagland.domain', base_dn='not a dn',
                bind_dn='svc-ucm', enabled=True,
            )
            config.bind_password = 'irrelevant'
            db.session.add(config)
            db.session.commit()
            assert lookup.realm_matches_connector('HAGLAND.DOMAIN') is False


class _FakeAttr:
    def __init__(self, value):
        self.value = value


class _FakeEntry:
    def __init__(self, attrs):
        self._attrs = attrs
        for key, value in attrs.items():
            setattr(self, key, _FakeAttr(value))

    def __contains__(self, key):
        return key in self._attrs


class _FakeConnection:
    def __init__(self, entries=None, search_raises=None):
        self.entries = entries or []
        self._search_raises = search_raises
        self.unbound = False

    def search(self, base_dn, filter_str, attributes=None):
        if self._search_raises:
            raise self._search_raises

    def unbind(self):
        self.unbound = True


def _configure(monkeypatch, app, enabled=True):
    with app.app_context():
        ADConnectorConfig.query.delete()
        config = ADConnectorConfig(
            server='dc1.hagland.domain', base_dn='DC=hagland,DC=domain',
            bind_dn='svc-ucm', enabled=enabled,
        )
        config.bind_password = 'irrelevant'
        db.session.add(config)
        db.session.commit()


class TestLookupComputerDnsHostname:
    def test_not_configured_returns_none(self, app):
        with app.app_context():
            ADConnectorConfig.query.delete()
            db.session.commit()
            assert lookup.lookup_computer_dns_hostname('WIN11$') is None

    def test_disabled_returns_none(self, app):
        _configure(None, app, enabled=False)
        with app.app_context():
            assert lookup.lookup_computer_dns_hostname('WIN11$') is None

    def test_bind_failure_returns_none(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        monkeypatch.setattr(lookup, '_connect', lambda config: (_ for _ in ()).throw(RuntimeError('bind failed')))
        with app.app_context():
            assert lookup.lookup_computer_dns_hostname('WIN11$') is None

    def test_computer_not_found_returns_none(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        monkeypatch.setattr(lookup, '_connect', lambda config: _FakeConnection(entries=[]))
        with app.app_context():
            assert lookup.lookup_computer_dns_hostname('WIN11$') is None

    def test_empty_attribute_returns_none(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        entry = _FakeEntry({'dNSHostName': ''})
        monkeypatch.setattr(lookup, '_connect', lambda config: _FakeConnection(entries=[entry]))
        with app.app_context():
            assert lookup.lookup_computer_dns_hostname('WIN11$') is None

    def test_missing_attribute_returns_none(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        entry = _FakeEntry({})
        monkeypatch.setattr(lookup, '_connect', lambda config: _FakeConnection(entries=[entry]))
        with app.app_context():
            assert lookup.lookup_computer_dns_hostname('WIN11$') is None

    def test_search_exception_returns_none(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        monkeypatch.setattr(
            lookup, '_connect',
            lambda config: _FakeConnection(search_raises=RuntimeError('search failed')),
        )
        with app.app_context():
            assert lookup.lookup_computer_dns_hostname('WIN11$') is None

    def test_success_returns_dns_hostname(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        entry = _FakeEntry({'dNSHostName': 'win11.hagland.domain'})
        monkeypatch.setattr(lookup, '_connect', lambda config: _FakeConnection(entries=[entry]))
        with app.app_context():
            assert lookup.lookup_computer_dns_hostname('WIN11$') == 'win11.hagland.domain'


class _FakeSequentialConnection:
    """Like ``_FakeConnection`` but returns a different ``entries`` list on
    each successive ``search()`` call -- needed for ``is_member_of_group``,
    which searches once to resolve a plain group name to a DN and again to
    check membership.
    """
    def __init__(self, entries_sequence):
        self._entries_sequence = list(entries_sequence)
        self.entries = []
        self.unbound = False

    def search(self, base_dn, filter_str, attributes=None):
        self.entries = self._entries_sequence.pop(0) if self._entries_sequence else []

    def unbind(self):
        self.unbound = True


class TestIsMemberOfGroup:
    def test_not_configured_returns_false(self, app):
        with app.app_context():
            ADConnectorConfig.query.delete()
            db.session.commit()
            assert lookup.is_member_of_group('alice', 'VPN-Enroll') is False

    def test_disabled_returns_false(self, app):
        _configure(None, app, enabled=False)
        with app.app_context():
            assert lookup.is_member_of_group('alice', 'VPN-Enroll') is False

    def test_empty_sam_account_name_returns_false(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        with app.app_context():
            assert lookup.is_member_of_group('', 'VPN-Enroll') is False
            assert lookup.is_member_of_group(None, 'VPN-Enroll') is False

    def test_empty_group_returns_false(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        with app.app_context():
            assert lookup.is_member_of_group('alice', '') is False
            assert lookup.is_member_of_group('alice', None) is False

    def test_bind_failure_returns_false(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        monkeypatch.setattr(lookup, '_connect', lambda config: (_ for _ in ()).throw(RuntimeError('bind failed')))
        with app.app_context():
            assert lookup.is_member_of_group('alice', 'VPN-Enroll') is False

    def test_group_name_not_found_returns_false(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        monkeypatch.setattr(lookup, '_connect', lambda config: _FakeSequentialConnection([[]]))
        with app.app_context():
            assert lookup.is_member_of_group('alice', 'VPN-Enroll') is False

    def test_member_by_group_name(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        group_entry = _FakeEntry({})
        group_entry.entry_dn = 'CN=VPN-Enroll,OU=Groups,DC=hagland,DC=domain'
        member_entry = _FakeEntry({'sAMAccountName': 'alice'})
        monkeypatch.setattr(
            lookup, '_connect',
            lambda config: _FakeSequentialConnection([[group_entry], [member_entry]]),
        )
        with app.app_context():
            assert lookup.is_member_of_group('alice', 'VPN-Enroll') is True

    def test_not_member_by_group_name(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        group_entry = _FakeEntry({})
        group_entry.entry_dn = 'CN=VPN-Enroll,OU=Groups,DC=hagland,DC=domain'
        monkeypatch.setattr(
            lookup, '_connect',
            lambda config: _FakeSequentialConnection([[group_entry], []]),
        )
        with app.app_context():
            assert lookup.is_member_of_group('alice', 'VPN-Enroll') is False

    def test_member_by_group_dn_skips_resolution_search(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        member_entry = _FakeEntry({'sAMAccountName': 'alice'})
        monkeypatch.setattr(
            lookup, '_connect',
            lambda config: _FakeSequentialConnection([[member_entry]]),
        )
        with app.app_context():
            assert lookup.is_member_of_group(
                'alice', 'CN=VPN-Enroll,OU=Groups,DC=hagland,DC=domain'
            ) is True

    def test_search_exception_returns_false(self, app, monkeypatch):
        _configure(None, app, enabled=True)
        monkeypatch.setattr(
            lookup, '_connect',
            lambda config: _FakeConnection(search_raises=RuntimeError('search failed')),
        )
        with app.app_context():
            assert lookup.is_member_of_group('alice', 'VPN-Enroll') is False

    def test_machine_principal_sam_account_name(self, app, monkeypatch):
        """A trailing '$' on a machine account's sAMAccountName is passed
        through unchanged -- it's a real part of the value, not stripped."""
        _configure(None, app, enabled=True)
        group_entry = _FakeEntry({})
        group_entry.entry_dn = 'CN=Enroll-Machines,OU=Groups,DC=hagland,DC=domain'
        member_entry = _FakeEntry({'sAMAccountName': 'WIN11$'})
        monkeypatch.setattr(
            lookup, '_connect',
            lambda config: _FakeSequentialConnection([[group_entry], [member_entry]]),
        )
        with app.app_context():
            assert lookup.is_member_of_group('WIN11$', 'Enroll-Machines') is True
