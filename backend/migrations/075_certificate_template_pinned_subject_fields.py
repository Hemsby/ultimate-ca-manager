"""Migration 075: add pinned_subject_fields column to certificate_templates.

Optional per-field subject pins (O/OU/C/ST/L) that override whatever a
client's CSR or AD-derivation supplies for that field on WSTEP issuance,
while CN/SAN stay dynamic. Stored as a JSON dict of only the fields
actually pinned, e.g. {"O": "Acme Corp", "OU": "IT"}. Defaults to NULL (no
pins), matching every other per-template WSTEP opt-in -- existing
templates keep issuing exactly as before until an admin opts one in.

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
        logger.info("075: certificate_templates table absent, skipping")
        return

    cur = conn.execute("PRAGMA table_info(certificate_templates)")
    cols = {row[1] for row in cur.fetchall()}
    if 'pinned_subject_fields' in cols:
        logger.info("075: pinned_subject_fields column already present, skipping")
        return

    conn.execute(
        "ALTER TABLE certificate_templates ADD COLUMN pinned_subject_fields TEXT"
    )
    conn.commit()
    logger.info("075: added pinned_subject_fields column to certificate_templates (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    if 'certificate_templates' not in set(insp.get_table_names()):
        logger.info("075: certificate_templates table absent, skipping")
        return

    cols = {c['name'] for c in insp.get_columns('certificate_templates')}
    if 'pinned_subject_fields' in cols:
        logger.info("075: pinned_subject_fields column already present, skipping")
        return

    conn.execute(
        text("ALTER TABLE certificate_templates ADD COLUMN pinned_subject_fields TEXT")
    )
    logger.info("075: added pinned_subject_fields column to certificate_templates (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # SQLite has no simple DROP COLUMN -- no-op
    pass
