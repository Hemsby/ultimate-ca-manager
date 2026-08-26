"""Migration 080: add is_external column to crl_metadata.

Supports externally-signed CRL upload for key-less / offline CAs (#302):
a CRL generated next to an offline root (or any CA whose key UCM does not
hold) can be uploaded and served at the CA's CDP endpoint. The flag marks
such rows so the scheduler/generation paths never try to supersede them
with a self-signed CRL and OCSP knows to consult the uploaded CRL.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    cur = conn.execute("PRAGMA table_info(crl_metadata)")
    cols = {row[1] for row in cur.fetchall()}
    if 'is_external' not in cols:
        conn.execute(
            "ALTER TABLE crl_metadata ADD COLUMN is_external BOOLEAN DEFAULT 0"
        )
        logger.info("080: added is_external column to crl_metadata (SQLite)")
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    cols = {c['name'] for c in inspect(conn).get_columns('crl_metadata')}
    if 'is_external' not in cols:
        conn.execute(text(
            "ALTER TABLE crl_metadata ADD COLUMN is_external BOOLEAN DEFAULT FALSE"
        ))
        logger.info("080: added is_external column to crl_metadata (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # SQLite has no simple DROP COLUMN pre-3.35; the column is harmless if
    # left behind (same policy as migration 079).
    pass
