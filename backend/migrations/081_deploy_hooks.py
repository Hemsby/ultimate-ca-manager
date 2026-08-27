"""Migration 081: deploy hooks tables (#299).

Push issued/renewed certificates to remote hosts over SFTP and run a fixed
reload command over SSH:

- deploy_targets: one row per remote host (SSH credentials encrypted at rest,
  host key pinned on first connect, one admin-defined reload command)
- deploy_bindings: certificate <-> target attachment with fixed destination
  paths for cert / key / fullchain
- deploy_deliveries: durable delivery queue (same model as webhook_deliveries:
  pending rows drained by a scheduler task with retry/backoff)
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

_SQLITE_TABLES = {
    'deploy_targets': """
        CREATE TABLE deploy_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(120) NOT NULL UNIQUE,
            host VARCHAR(255) NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username VARCHAR(120) NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT,
            host_key TEXT,
            reload_command VARCHAR(512),
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME,
            created_by VARCHAR(80),
            last_success_at DATETIME,
            last_failure_at DATETIME,
            failure_count INTEGER NOT NULL DEFAULT 0
        )
    """,
    'deploy_bindings': """
        CREATE TABLE deploy_bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL REFERENCES deploy_targets (id),
            certificate_id INTEGER NOT NULL REFERENCES certificates (id),
            cert_path VARCHAR(512),
            key_path VARCHAR(512),
            fullchain_path VARCHAR(512),
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME,
            created_by VARCHAR(80),
            UNIQUE(target_id, certificate_id)
        )
    """,
    'deploy_deliveries': """
        CREATE TABLE deploy_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binding_id INTEGER NOT NULL,
            event_type VARCHAR(32) NOT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 5,
            next_attempt_at DATETIME,
            last_error TEXT,
            detail TEXT,
            triggered_by VARCHAR(80),
            created_at DATETIME,
            delivered_at DATETIME
        )
    """,
}

_SQLITE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_deploy_bindings_certificate_id ON deploy_bindings (certificate_id)",
    "CREATE INDEX IF NOT EXISTS ix_deploy_bindings_target_id ON deploy_bindings (target_id)",
    "CREATE INDEX IF NOT EXISTS ix_deploy_deliveries_binding_id ON deploy_deliveries (binding_id)",
    "CREATE INDEX IF NOT EXISTS ix_deploy_deliveries_status ON deploy_deliveries (status)",
    "CREATE INDEX IF NOT EXISTS ix_deploy_deliveries_next_attempt_at ON deploy_deliveries (next_attempt_at)",
]


def _upgrade_sqlite(conn):
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing = {row[0] for row in cur.fetchall()}
    for table, ddl in _SQLITE_TABLES.items():
        if table not in existing:
            conn.execute(ddl)
            logger.info(f"081: created {table} (SQLite)")
    for idx in _SQLITE_INDEXES:
        conn.execute(idx)
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    existing = set(inspect(conn).get_table_names())
    if 'deploy_targets' not in existing:
        conn.execute(text("""
            CREATE TABLE deploy_targets (
                id SERIAL PRIMARY KEY,
                name VARCHAR(120) NOT NULL UNIQUE,
                host VARCHAR(255) NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username VARCHAR(120) NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT,
                host_key TEXT,
                reload_command VARCHAR(512),
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP,
                created_by VARCHAR(80),
                last_success_at TIMESTAMP,
                last_failure_at TIMESTAMP,
                failure_count INTEGER NOT NULL DEFAULT 0
            )
        """))
        logger.info("081: created deploy_targets (PostgreSQL)")
    if 'deploy_bindings' not in existing:
        conn.execute(text("""
            CREATE TABLE deploy_bindings (
                id SERIAL PRIMARY KEY,
                target_id INTEGER NOT NULL REFERENCES deploy_targets (id),
                certificate_id INTEGER NOT NULL REFERENCES certificates (id),
                cert_path VARCHAR(512),
                key_path VARCHAR(512),
                fullchain_path VARCHAR(512),
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP,
                created_by VARCHAR(80),
                UNIQUE(target_id, certificate_id)
            )
        """))
        logger.info("081: created deploy_bindings (PostgreSQL)")
    if 'deploy_deliveries' not in existing:
        conn.execute(text("""
            CREATE TABLE deploy_deliveries (
                id SERIAL PRIMARY KEY,
                binding_id INTEGER NOT NULL,
                event_type VARCHAR(32) NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 5,
                next_attempt_at TIMESTAMP,
                last_error TEXT,
                detail TEXT,
                triggered_by VARCHAR(80),
                created_at TIMESTAMP,
                delivered_at TIMESTAMP
            )
        """))
        logger.info("081: created deploy_deliveries (PostgreSQL)")
    for idx in _SQLITE_INDEXES:
        conn.execute(text(idx))


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # Tables are harmless if left behind (same policy as earlier migrations).
    pass
