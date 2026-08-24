"""Migration 079: add csr column to certificate_authorities.

Supports the "Signed by external CA (CSR)" creation mode (#298): a CA row may
exist before its certificate does. The pending state uses the sentinel
crt = '' (the NOT NULL constraint is preserved, so no SQLite table rebuild —
the FK from revoked_serials added in migration 078 stays intact). The pending
CSR is stored here as base64-encoded PEM, the same encoding as
Certificate.csr; NULL means no CSR is outstanding.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    cur = conn.execute("PRAGMA table_info(certificate_authorities)")
    cols = {row[1] for row in cur.fetchall()}
    if 'csr' not in cols:
        conn.execute("ALTER TABLE certificate_authorities ADD COLUMN csr TEXT")
        logger.info("079: added csr column to certificate_authorities (SQLite)")
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    cols = {c['name'] for c in inspect(conn).get_columns('certificate_authorities')}
    if 'csr' not in cols:
        conn.execute(text("ALTER TABLE certificate_authorities ADD COLUMN csr TEXT"))
        logger.info("079: added csr column to certificate_authorities (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # SQLite has no simple DROP COLUMN pre-3.35; the column is harmless if
    # left behind (same policy as migration 075).
    pass
