"""Migration 071: add autoenroll_enabled column to certificate_templates.

Per-template opt-in for MS-XCEP's GetPolicies to advertise autoEnroll=true
for a template, mirroring real ADCS's own Enroll-vs-Autoenroll distinction
(two separate permission bits on a template's ACL: Enroll lets a principal
manually request a certificate; Autoenroll is required separately before
unattended background autoenrollment will pick the template up at all).
UCM previously advertised autoEnroll=true unconditionally for every active
template, so any Kerberos-authenticated principal at logon got prompted to
enroll for every template exposed by the CA, not just the ones actually
meant for unattended enrollment.

Defaults to false: existing templates require an explicit admin opt-in
before autoenrollment will offer them, matching real ADCS's own default of
granting Enroll broadly but Autoenroll narrowly.

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
        logger.info("071: certificate_templates table absent, skipping")
        return

    cur = conn.execute("PRAGMA table_info(certificate_templates)")
    cols = {row[1] for row in cur.fetchall()}
    if 'autoenroll_enabled' in cols:
        logger.info("071: autoenroll_enabled column already present, skipping")
        return

    conn.execute(
        "ALTER TABLE certificate_templates ADD COLUMN autoenroll_enabled BOOLEAN DEFAULT 0"
    )
    conn.commit()
    logger.info("071: added autoenroll_enabled column to certificate_templates (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    if 'certificate_templates' not in set(insp.get_table_names()):
        logger.info("071: certificate_templates table absent, skipping")
        return

    cols = {c['name'] for c in insp.get_columns('certificate_templates')}
    if 'autoenroll_enabled' in cols:
        logger.info("071: autoenroll_enabled column already present, skipping")
        return

    conn.execute(
        text("ALTER TABLE certificate_templates ADD COLUMN autoenroll_enabled BOOLEAN DEFAULT FALSE")
    )
    logger.info("071: added autoenroll_enabled column to certificate_templates (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # SQLite has no simple DROP COLUMN — no-op
    pass
