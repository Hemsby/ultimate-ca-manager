"""Migration 078: create revoked_serials table + add renewed_at column.

When a certificate is revoked and later deleted (e.g. after renewal), the
revocation must still appear in CRLs and OCSP responses until the original
certificate's notAfter has passed. This table holds the minimal data needed
to generate those revocation entries independently of the certificates table.

Additionally, `renewed_at` (DateTime) and `renewed_times` (Integer) columns
are added to the `certificates` table to track the last renewal timestamp and
the number of renewals. NULL/0 means the certificate has never been renewed
(original issuance). `created_at` is preserved across renewals so the original
issuance date is never lost.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


_DDL_SQLITE = """
CREATE TABLE IF NOT EXISTS revoked_serials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    caref VARCHAR(36) NOT NULL,
    serial_number VARCHAR(100) NOT NULL,
    revoked_at DATETIME NOT NULL,
    revoke_reason VARCHAR(100),
    invalidity_at DATETIME,
    valid_to DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    certificate_id INTEGER,
    FOREIGN KEY (caref) REFERENCES certificate_authorities(refid)
)
"""

_DDL_PG = """
CREATE TABLE IF NOT EXISTS revoked_serials (
    id SERIAL PRIMARY KEY,
    caref VARCHAR(36) NOT NULL REFERENCES certificate_authorities(refid),
    serial_number VARCHAR(100) NOT NULL,
    revoked_at TIMESTAMP NOT NULL,
    revoke_reason VARCHAR(100),
    invalidity_at TIMESTAMP,
    valid_to TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    certificate_id INTEGER
)
"""

_INDEX_CAREF = "CREATE INDEX IF NOT EXISTS ix_revoked_serials_caref ON revoked_serials (caref)"
_INDEX_SERIAL = "CREATE INDEX IF NOT EXISTS ix_revoked_serials_serial_number ON revoked_serials (serial_number)"
_INDEX_CERT_ID = "CREATE INDEX IF NOT EXISTS ix_revoked_serials_certificate_id ON revoked_serials (certificate_id)"


def _upgrade_sqlite(conn):
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='revoked_serials'"
    )
    if cur.fetchone():
        logger.info("078: revoked_serials table already exists, skipping table creation")
    else:
        conn.execute(_DDL_SQLITE)
        logger.info("078: created revoked_serials table (SQLite)")

    # Indexes are created unconditionally (IF NOT EXISTS) so they are
    # added even when the table pre-exists without them.
    conn.execute(_INDEX_CAREF)
    conn.execute(_INDEX_SERIAL)
    conn.execute(_INDEX_CERT_ID)

    # Add renewed_at and renewed_times columns to certificates table
    cur = conn.execute("PRAGMA table_info(certificates)")
    col_names = [row[1] for row in cur.fetchall()]
    if 'renewed_at' not in col_names:
        conn.execute("ALTER TABLE certificates ADD COLUMN renewed_at DATETIME")
        logger.info("078: added renewed_at column to certificates (SQLite)")
    if 'renewed_times' not in col_names:
        conn.execute("ALTER TABLE certificates ADD COLUMN renewed_times INTEGER DEFAULT 0 NOT NULL")
        logger.info("078: added renewed_times column to certificates (SQLite)")

    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    if 'revoked_serials' in set(insp.get_table_names()):
        logger.info("078: revoked_serials table already exists, skipping table creation")
    else:
        conn.execute(text(_DDL_PG))
        logger.info("078: created revoked_serials table (PostgreSQL)")

    # Indexes are created unconditionally (IF NOT EXISTS) so they are
    # added even when the table pre-exists without them.
    conn.execute(text(_INDEX_CAREF))
    conn.execute(text(_INDEX_SERIAL))
    conn.execute(text(_INDEX_CERT_ID))

    # Add renewed_at and renewed_times columns to certificates table
    cert_cols = {col['name'] for col in insp.get_columns('certificates')}
    if 'renewed_at' not in cert_cols:
        conn.execute(text("ALTER TABLE certificates ADD COLUMN renewed_at TIMESTAMP"))
        logger.info("078: added renewed_at column to certificates (PostgreSQL)")
    if 'renewed_times' not in cert_cols:
        conn.execute(text("ALTER TABLE certificates ADD COLUMN renewed_times INTEGER DEFAULT 0 NOT NULL"))
        logger.info("078: added renewed_times column to certificates (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        # SQLite doesn't support DROP COLUMN before 3.35; recreate is complex.
        # The renewed_at column is harmless if left behind.
        conn.execute("DROP TABLE IF EXISTS revoked_serials")
        conn.commit()
    else:
        from sqlalchemy import text
        conn.execute(text("ALTER TABLE certificates DROP COLUMN IF EXISTS renewed_at"))
        conn.execute(text("ALTER TABLE certificates DROP COLUMN IF EXISTS renewed_times"))
        conn.execute(text("DROP TABLE IF EXISTS revoked_serials"))
