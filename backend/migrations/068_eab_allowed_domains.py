"""Migration 068: per-EAB allowed domain patterns.
 
Adds acme_eab_credentials.allowed_domains (JSON array, TEXT).
Existing credentials are backfilled with ["*"] (unrestricted) so
upgrades do not break accounts already bound to a credential.
 
Dual-backend (SQLite + PostgreSQL).
"""
 
import logging
import sqlite3
 
logger = logging.getLogger(__name__)
pg_compatible = True
 
_BACKFILL = '["*"]'
 
 
def _upgrade_sqlite(conn):
    tables = {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if 'acme_eab_credentials' not in tables:
        logger.info('[068] acme_eab_credentials absent, skipping (SQLite)')
        return
 
    columns = {
        row[1] for row in conn.execute(
            'PRAGMA table_info(acme_eab_credentials)'
        ).fetchall()
    }
    if 'allowed_domains' not in columns:
        conn.execute(
            'ALTER TABLE acme_eab_credentials ADD COLUMN allowed_domains TEXT'
        )
        conn.execute(
            'UPDATE acme_eab_credentials SET allowed_domains = ? '
            'WHERE allowed_domains IS NULL',
            (_BACKFILL,),
        )
    conn.commit()
    logger.info('[068] added EAB allowed_domains (SQLite)')
 
 
def _upgrade_pg(conn):
    from sqlalchemy import inspect, text
 
    inspector = inspect(conn)
    if 'acme_eab_credentials' not in set(inspector.get_table_names()):
        logger.info('[068] acme_eab_credentials absent, skipping (PostgreSQL)')
        return
 
    columns = {
        column['name'] for column in inspector.get_columns('acme_eab_credentials')
    }
    if 'allowed_domains' not in columns:
        conn.execute(text(
            'ALTER TABLE acme_eab_credentials ADD COLUMN allowed_domains TEXT'
        ))
        conn.execute(text(
            "UPDATE acme_eab_credentials SET allowed_domains = :backfill "
            "WHERE allowed_domains IS NULL"
        ), {'backfill': _BACKFILL})
    logger.info('[068] added EAB allowed_domains (PostgreSQL)')
 
 
def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)
 
 
def downgrade(conn):
    """Keep the column when rolling application code back."""
    pass