"""Migration 094: let certificate expiry alerts skip ACME-issued certificates.

An ACME client renews its own certificates, so alerting the expiry
recipients about them is noise (#386). Off by default: existing alerts keep
covering every certificate until an administrator opts out.
"""

import sqlite3

pg_compatible = True


def _upgrade_sqlite(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(notification_config)")}
    if 'exclude_acme' not in columns:
        conn.execute(
            "ALTER TABLE notification_config ADD COLUMN exclude_acme BOOLEAN NOT NULL DEFAULT 0")
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import text

    conn.execute(text(
        "ALTER TABLE notification_config ADD COLUMN IF NOT EXISTS "
        "exclude_acme BOOLEAN NOT NULL DEFAULT FALSE"))


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # Kept: older versions ignore the column.
    pass
