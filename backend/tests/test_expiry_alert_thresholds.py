"""Certificate expiry alerts: every selected threshold is stored (#323) and the
scheduled job reads the saved configuration and fires each threshold once per
validity period (#324)."""
import importlib
import json
import sqlite3
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

import services.email_service as email_service_module
from models import db, Certificate
from models.email_notification import NotificationConfig, NotificationLog
from services.email_service import EmailService
from services.notification_service import NotificationService
from utils.datetime_utils import utc_now


def _migration():
    return importlib.import_module('migrations.082_expiry_alert_thresholds')


def test_migration_082_adds_columns_and_keeps_single_threshold():
    conn = sqlite3.connect(':memory:')
    conn.execute(
        'CREATE TABLE notification_config (id INTEGER PRIMARY KEY, type TEXT, '
        'enabled BOOLEAN, days_before INTEGER, recipients TEXT)'
    )
    conn.execute(
        'CREATE TABLE notification_log (id INTEGER PRIMARY KEY, type TEXT, '
        'resource_type TEXT, resource_id TEXT, status TEXT, sent_at DATETIME)'
    )
    conn.execute(
        "INSERT INTO notification_config (type, enabled, days_before, recipients) "
        "VALUES ('cert_expiring', 1, 14, '[]')"
    )
    conn.commit()

    migration = _migration()
    migration.upgrade(conn)
    migration.upgrade(conn)  # idempotent

    cols = {row[1] for row in conn.execute('PRAGMA table_info(notification_config)')}
    assert {'alert_days', 'include_revoked'} <= cols
    log_cols = {row[1] for row in conn.execute('PRAGMA table_info(notification_log)')}
    assert 'threshold_days' in log_cols
    row = conn.execute(
        "SELECT alert_days, days_before FROM notification_config WHERE type = 'cert_expiring'"
    ).fetchone()
    assert json.loads(row[0]) == [14]
    assert row[1] == 14


class _SmtpConfig:
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
    smtp_auth = False


@pytest.fixture
def smtp_spy(app, monkeypatch):
    monkeypatch.setattr(EmailService, 'get_smtp_config', staticmethod(lambda: _SmtpConfig()))
    server = MagicMock()
    factory = MagicMock(return_value=server)
    monkeypatch.setattr(email_service_module.smtplib, 'SMTP', factory)
    monkeypatch.setattr(email_service_module.smtplib, 'SMTP_SSL', factory)
    return server


@pytest.fixture
def expiry_config(app):
    """cert_expiring row with a 30/14/7/1 selection and one recipient; restored after."""
    with app.app_context():
        config = NotificationConfig.query.filter_by(type='cert_expiring').first()
        snapshot = None
        if config:
            snapshot = (config.enabled, config.days_before, config.alert_days,
                        config.include_revoked, config.recipients)
        else:
            config = NotificationConfig(type='cert_expiring')
            db.session.add(config)
        config.enabled = True
        config.set_alert_days([30, 14, 7, 1])
        config.include_revoked = False
        config.recipients = json.dumps(['ops@example.com'])
        db.session.commit()
        config_id = config.id
    yield config_id
    with app.app_context():
        config = db.session.get(NotificationConfig, config_id)
        if snapshot:
            (config.enabled, config.days_before, config.alert_days,
             config.include_revoked, config.recipients) = snapshot
            db.session.commit()
        else:
            db.session.delete(config)
            db.session.commit()


def _thresholds_sent(app, refid):
    with app.app_context():
        rows = NotificationLog.query.filter_by(
            type='cert_expiring', resource_type='certificate', resource_id=refid, status='sent'
        ).order_by(NotificationLog.id).all()
        return [r.threshold_days for r in rows]


def _set_validity(app, cert_id, *, days_left, valid_from=None):
    with app.app_context():
        cert = db.session.get(Certificate, cert_id)
        now = utc_now()
        cert.valid_to = now + timedelta(days=days_left)
        cert.valid_from = valid_from if valid_from is not None else now - timedelta(days=100)
        db.session.commit()
        return cert.refid


def _run(app):
    with app.app_context():
        return NotificationService.run_scheduled_checks()


class TestThresholdEscalation:
    def test_each_threshold_fires_once_per_validity_period(self, app, create_cert, expiry_config, smtp_spy):
        cert = create_cert(cn='expiry-thresholds.example.com')
        refid = _set_validity(app, cert['id'], days_left=20)

        _run(app)
        assert _thresholds_sent(app, refid) == [30]
        _run(app)
        assert _thresholds_sent(app, refid) == [30], 'no daily repeat inside the same window'

        _set_validity(app, cert['id'], days_left=10)
        _run(app)
        assert _thresholds_sent(app, refid) == [30, 14]

        _set_validity(app, cert['id'], days_left=5)
        _run(app)
        assert _thresholds_sent(app, refid) == [30, 14, 7]

        with app.app_context():
            c = db.session.get(Certificate, cert['id'])
            c.valid_to = utc_now() + timedelta(hours=12)
            db.session.commit()
        _run(app)
        assert _thresholds_sent(app, refid) == [30, 14, 7, 1]
        _run(app)
        assert _thresholds_sent(app, refid) == [30, 14, 7, 1]

    def test_renewal_starts_a_new_alert_cycle(self, app, create_cert, expiry_config, smtp_spy):
        cert = create_cert(cn='expiry-renewed.example.com')
        refid = _set_validity(app, cert['id'], days_left=20)
        _run(app)
        assert _thresholds_sent(app, refid) == [30]

        # Renewed: new validity period starting after the alert went out
        _set_validity(app, cert['id'], days_left=20, valid_from=utc_now() + timedelta(seconds=2))
        _run(app)
        assert _thresholds_sent(app, refid) == [30, 30]

    def test_revoked_certificates_follow_the_toggle(self, app, create_cert, expiry_config, smtp_spy):
        cert = create_cert(cn='expiry-revoked.example.com')
        refid = _set_validity(app, cert['id'], days_left=10)
        with app.app_context():
            c = db.session.get(Certificate, cert['id'])
            c.revoked = True
            db.session.commit()

        _run(app)
        assert _thresholds_sent(app, refid) == []

        with app.app_context():
            db.session.get(NotificationConfig, expiry_config).include_revoked = True
            db.session.commit()
        _run(app)
        assert _thresholds_sent(app, refid) == [14]

    def test_disabled_or_without_recipients_sends_nothing(self, app, create_cert, expiry_config, smtp_spy):
        cert = create_cert(cn='expiry-disabled.example.com')
        refid = _set_validity(app, cert['id'], days_left=3)

        with app.app_context():
            db.session.get(NotificationConfig, expiry_config).enabled = False
            db.session.commit()
        _run(app)
        assert _thresholds_sent(app, refid) == []

        with app.app_context():
            config = db.session.get(NotificationConfig, expiry_config)
            config.enabled = True
            config.recipients = '[]'
            db.session.commit()
        _run(app)
        assert _thresholds_sent(app, refid) == []

    def test_configured_recipients_are_used(self, app, create_cert, expiry_config, smtp_spy):
        cert = create_cert(cn='expiry-recipients.example.com')
        _set_validity(app, cert['id'], days_left=2)
        _run(app)
        sent_to = [call.args[1] for call in smtp_spy.sendmail.call_args_list]
        assert any('ops@example.com' in rcpts for rcpts in sent_to)
        assert all('ucm@example.com' not in rcpts for rcpts in sent_to), \
            'the From address is not appended as a recipient'
