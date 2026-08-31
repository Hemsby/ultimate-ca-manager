"""
Send-time recipient validation (#303): invalid addresses are skipped with a
log line instead of being handed to SMTP; nothing is rejected at input time.
"""
from unittest.mock import MagicMock

import pytest

import services.email_service as email_service_module
from services.email_service import EmailService


class _Config:
    enabled = True
    smtp_host = 'smtp.example.com'
    smtp_port = 25
    smtp_use_ssl = False
    smtp_use_tls = False
    smtp_from = 'ucm@example.com'
    smtp_from_name = 'UCM'
    smtp_username = None
    smtp_user = None
    smtp_password = None
    smtp_content_type = 'html'
    smtp_auth_method = 'password'


@pytest.fixture
def smtp_spy(app, monkeypatch):
    monkeypatch.setattr(EmailService, 'get_smtp_config', staticmethod(lambda: _Config()))
    server = MagicMock()
    smtp_factory = MagicMock(return_value=server)
    monkeypatch.setattr(email_service_module.smtplib, 'SMTP', smtp_factory)
    monkeypatch.setattr(email_service_module.smtplib, 'SMTP_SSL', smtp_factory)
    return smtp_factory, server


class TestIsValidAddress:
    @pytest.mark.parametrize('addr, expected', [
        ('user@example.com', True),
        ('first.last+tag@sub.example.co', True),
        ('backup-server', False),          # "tag only" contact
        ('user@localhost', True),           # valid internal SMTP domain
        ('user@[192.0.2.1]', True),         # valid address-literal domain
        ('user@@example.com', False),
        ('user @example.com', False),
        ('', False),
        ('a' * 350 + '@example.com', False),
    ])
    def test_shapes(self, addr, expected):
        assert EmailService._is_valid_address(addr) is expected


class TestSendTimeFiltering:
    def _send(self, recipients):
        return EmailService.send_email(
            recipients=recipients,
            subject='s', body_html='<p>b</p>', notification_type='test',
        )

    def test_mixed_recipients_only_valid_are_sent(self, app, smtp_spy, caplog):
        factory, server = smtp_spy
        with app.app_context():
            ok, _msg = self._send(['good@example.com', 'backup-server'])
        assert ok is True
        assert server.sendmail.call_count == 1
        _from, to_list, _body = server.sendmail.call_args[0]
        assert to_list == ['good@example.com']
        assert any('invalid email recipient' in r.message for r in caplog.records)

    def test_all_invalid_never_touches_smtp(self, app, smtp_spy):
        factory, _server = smtp_spy
        with app.app_context():
            ok, msg = self._send(['backup-server', 'not-an-email'])
        assert ok is False
        assert 'valid recipient' in msg
        assert factory.call_count == 0

    def test_all_valid_unchanged(self, app, smtp_spy):
        factory, _server = smtp_spy
        with app.app_context():
            ok, _msg = self._send(['a@example.com', 'b@example.org'])
        assert ok is True
        assert factory.call_count == 1

    def test_internal_mailbox_is_sent(self, app, smtp_spy):
        _factory, server = smtp_spy
        with app.app_context():
            ok, _msg = self._send(['alerts@mailhost'])
        assert ok is True
        assert server.sendmail.call_args[0][1] == ['alerts@mailhost']
