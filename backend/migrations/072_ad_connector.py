"""Migration 072: ad_connector_config table.

Single-row Active Directory connector configuration -- lets UCM query AD
directly (independent of SSO's own, unrelated LDAP provider config) to
resolve a Kerberos machine principal to its computer object's dNSHostName,
for MS-WSTEP's naked-CSR subject derivation (GPO machine autoenrollment).

Dual-backend (SQLite + PostgreSQL).
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

_SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS ad_connector_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server VARCHAR(500),
    port INTEGER DEFAULT 389,
    use_ssl BOOLEAN DEFAULT 0,
    verify_ssl BOOLEAN DEFAULT 1,
    ca_bundle TEXT,
    base_dn VARCHAR(500),
    bind_dn VARCHAR(500),
    bind_password VARCHAR(500),
    enabled BOOLEAN DEFAULT 0,
    last_test_at DATETIME,
    last_test_result VARCHAR(500),
    created_at DATETIME,
    updated_at DATETIME,
    created_by VARCHAR(80)
)
"""

_PG_DDL = """
CREATE TABLE IF NOT EXISTS ad_connector_config (
    id SERIAL PRIMARY KEY,
    server VARCHAR(500),
    port INTEGER DEFAULT 389,
    use_ssl BOOLEAN DEFAULT FALSE,
    verify_ssl BOOLEAN DEFAULT TRUE,
    ca_bundle TEXT,
    base_dn VARCHAR(500),
    bind_dn VARCHAR(500),
    bind_password VARCHAR(500),
    enabled BOOLEAN DEFAULT FALSE,
    last_test_at TIMESTAMP,
    last_test_result VARCHAR(500),
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    created_by VARCHAR(80)
)
"""


def _upgrade_sqlite(conn):
    conn.execute(_SQLITE_DDL)
    conn.commit()
    logger.info("[072] created ad_connector_config (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import text
    conn.execute(text(_PG_DDL))
    logger.info("[072] created ad_connector_config (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        conn.execute("DROP TABLE IF EXISTS ad_connector_config")
        conn.commit()
    else:
        from sqlalchemy import text
        conn.execute(text("DROP TABLE IF EXISTS ad_connector_config"))
