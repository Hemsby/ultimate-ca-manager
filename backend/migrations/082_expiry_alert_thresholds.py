"""Migration 082: expiry alert thresholds and revoked filter (#323, #324).

- notification_config.alert_days (TEXT, JSON list of day thresholds) becomes
  the source of truth for certificate expiry alerts. days_before is kept in
  sync (largest threshold) for the generic notifications screen and CRL
  alerts.
- notification_config.include_revoked (BOOLEAN) persists the UI toggle that
  was previously accepted and discarded.
- notification_log.threshold_days (INTEGER) records which threshold an
  expiry alert was sent for, so every selected threshold fires once per
  validity period instead of a daily reminder inside the largest window.

Existing cert_expiring rows keep their current single threshold as
[days_before] so nothing changes until the operator saves a new selection.
"""

import json
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    cols = {row[1] for row in conn.execute("PRAGMA table_info(notification_config)")}
    if 'alert_days' not in cols:
        conn.execute("ALTER TABLE notification_config ADD COLUMN alert_days TEXT")
        logger.info("082: added alert_days column to notification_config (SQLite)")
    if 'include_revoked' not in cols:
        conn.execute(
            "ALTER TABLE notification_config ADD COLUMN include_revoked BOOLEAN DEFAULT 0"
        )
        logger.info("082: added include_revoked column to notification_config (SQLite)")
    log_cols = {row[1] for row in conn.execute("PRAGMA table_info(notification_log)")}
    if 'threshold_days' not in log_cols:
        conn.execute("ALTER TABLE notification_log ADD COLUMN threshold_days INTEGER")
        logger.info("082: added threshold_days column to notification_log (SQLite)")
    row = conn.execute(
        "SELECT id, days_before FROM notification_config "
        "WHERE type = 'cert_expiring' AND alert_days IS NULL"
    ).fetchone()
    if row and row[1]:
        conn.execute(
            "UPDATE notification_config SET alert_days = ? WHERE id = ?",
            (json.dumps([int(row[1])]), row[0]),
        )
        logger.info("082: kept the existing cert_expiring threshold as [%s]", row[1])
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    cols = {c['name'] for c in inspector.get_columns('notification_config')}
    if 'alert_days' not in cols:
        conn.execute(text("ALTER TABLE notification_config ADD COLUMN alert_days TEXT"))
        logger.info("082: added alert_days column to notification_config (PostgreSQL)")
    if 'include_revoked' not in cols:
        conn.execute(text(
            "ALTER TABLE notification_config ADD COLUMN include_revoked BOOLEAN DEFAULT FALSE"
        ))
        logger.info("082: added include_revoked column to notification_config (PostgreSQL)")
    log_cols = {c['name'] for c in inspector.get_columns('notification_log')}
    if 'threshold_days' not in log_cols:
        conn.execute(text("ALTER TABLE notification_log ADD COLUMN threshold_days INTEGER"))
        logger.info("082: added threshold_days column to notification_log (PostgreSQL)")
    row = conn.execute(text(
        "SELECT id, days_before FROM notification_config "
        "WHERE type = 'cert_expiring' AND alert_days IS NULL"
    )).fetchone()
    if row and row[1]:
        conn.execute(
            text("UPDATE notification_config SET alert_days = :days WHERE id = :id"),
            {'days': json.dumps([int(row[1])]), 'id': row[0]},
        )
        logger.info("082: kept the existing cert_expiring threshold as [%s]", row[1])


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # Added columns are harmless if left behind (same policy as 079/080).
    pass
