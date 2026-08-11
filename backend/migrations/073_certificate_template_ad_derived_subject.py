"""Migration 073: add ad_derived_subject column to certificate_templates.

Per-template opt-in for MS-WSTEP to build the certificate's subject/SAN
from the requester's Active Directory object (via the AD Connector) rather
than from the CSR the client supplies -- mirrors how real ADCS lets an
admin configure this per-template (msPKI-Certificate-Name-Flag), instead
of inferring it from a hardcoded template-type set the way the existing
machine-autoenrollment path does. Defaults to false: existing templates
keep requiring an enrollee-supplied subject until an admin opts one in.

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
        logger.info("073: certificate_templates table absent, skipping")
        return

    cur = conn.execute("PRAGMA table_info(certificate_templates)")
    cols = {row[1] for row in cur.fetchall()}
    if 'ad_derived_subject' in cols:
        logger.info("073: ad_derived_subject column already present, skipping")
        return

    conn.execute(
        "ALTER TABLE certificate_templates ADD COLUMN ad_derived_subject BOOLEAN DEFAULT 0"
    )
    conn.commit()
    logger.info("073: added ad_derived_subject column to certificate_templates (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    if 'certificate_templates' not in set(insp.get_table_names()):
        logger.info("073: certificate_templates table absent, skipping")
        return

    cols = {c['name'] for c in insp.get_columns('certificate_templates')}
    if 'ad_derived_subject' in cols:
        logger.info("073: ad_derived_subject column already present, skipping")
        return

    conn.execute(
        text("ALTER TABLE certificate_templates ADD COLUMN ad_derived_subject BOOLEAN DEFAULT FALSE")
    )
    logger.info("073: added ad_derived_subject column to certificate_templates (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # SQLite has no simple DROP COLUMN — no-op
    pass
