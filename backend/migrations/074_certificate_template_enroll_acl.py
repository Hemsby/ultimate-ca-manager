"""Migration 074: add allowed_ad_group column to certificate_templates.

Optional per-template Enroll ACL: restricts WSTEP Kerberos-bound issuance
to principals belonging to a specific AD group, resolved via the AD
Connector. Defaults to NULL (no restriction), matching real ADCS's default
"any authenticated member can enroll" behavior -- existing templates keep
issuing unrestricted until an admin opts one in.

Idempotent and multi-backend (SQLite + PostgreSQL).
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='certificate_templates'"
    )
    if not cur.fetchone():
        logger.info("074: certificate_templates table absent, skipping")
        return

    cur = conn.execute("PRAGMA table_info(certificate_templates)")
    cols = {row[1] for row in cur.fetchall()}
    if 'allowed_ad_group' in cols:
        logger.info("074: allowed_ad_group column already present, skipping")
        return

    conn.execute(
        "ALTER TABLE certificate_templates ADD COLUMN allowed_ad_group VARCHAR(255)"
    )
    conn.commit()
    logger.info("074: added allowed_ad_group column to certificate_templates (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    if 'certificate_templates' not in set(insp.get_table_names()):
        logger.info("074: certificate_templates table absent, skipping")
        return

    cols = {c['name'] for c in insp.get_columns('certificate_templates')}
    if 'allowed_ad_group' in cols:
        logger.info("074: allowed_ad_group column already present, skipping")
        return

    conn.execute(
        text("ALTER TABLE certificate_templates ADD COLUMN allowed_ad_group VARCHAR(255)")
    )
    logger.info("074: added allowed_ad_group column to certificate_templates (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # SQLite has no simple DROP COLUMN -- no-op
    pass
