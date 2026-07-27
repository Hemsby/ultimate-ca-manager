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
