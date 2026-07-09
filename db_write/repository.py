from __future__ import annotations

import logging
from datetime import datetime, timezone

from psycopg2 import sql
from psycopg2.extensions import connection as PGConnection
from psycopg2.extras import Json, execute_values

from models import PyrusSite

logger = logging.getLogger(__name__)

# Таблица создаётся без указания схемы — резолвится через search_path
# соединения (db.get_connection уже открывает его с search_path=DB_SCHEMA).
_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS pyrus_sites (
    task_id          BIGINT PRIMARY KEY,
    directorate      TEXT,
    zabbix_hostname  TEXT,
    router_ip        TEXT,
    address          TEXT,
    address_source   TEXT,
    city             TEXT,
    channels         JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_pyrus_sites_zabbix_hostname ON pyrus_sites (zabbix_hostname);
CREATE INDEX IF NOT EXISTS ix_pyrus_sites_router_ip       ON pyrus_sites (router_ip);
"""

_UPSERT_SQL = """
INSERT INTO pyrus_sites
    (task_id, directorate, zabbix_hostname, router_ip, address, address_source, city, channels, updated_at)
VALUES %s
ON CONFLICT (task_id) DO UPDATE SET
    directorate     = EXCLUDED.directorate,
    zabbix_hostname = EXCLUDED.zabbix_hostname,
    router_ip       = EXCLUDED.router_ip,
    address         = EXCLUDED.address,
    address_source  = EXCLUDED.address_source,
    city            = EXCLUDED.city,
    channels        = EXCLUDED.channels,
    updated_at      = EXCLUDED.updated_at
"""


def init_schema(conn: PGConnection, schema: str) -> None:
    """Создаёт схему реестра Pyrus (если её ещё нет) и таблицу pyrus_sites в ней."""
    with conn.cursor() as cur:
        cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))
        cur.execute(_TABLE_SQL)
    conn.commit()
    logger.info("Схема БД реестра Pyrus готова (%s.pyrus_sites)", schema)


def _row(site: PyrusSite, now: datetime) -> tuple:
    return (
        site.task_id,
        site.directorate,
        site.zabbix_hostname,
        site.router_ip,
        site.address,
        site.address_source,
        site.city,
        Json([ch.model_dump() for ch in site.channels]),
        now,
    )


def sync_sites(conn: PGConnection, sites: list[PyrusSite], batch_size: int = 1000) -> int:
    """Батчевый upsert среза реестра Pyrus в БД (по task_id). Возвращает число сохранённых задач."""
    now = datetime.now(timezone.utc)
    rows = [_row(site, now) for site in sites]

    with conn.cursor() as cur:
        for i in range(0, len(rows), batch_size):
            execute_values(cur, _UPSERT_SQL, rows[i:i + batch_size])
    conn.commit()

    logger.info("В БД сохранено задач реестра Pyrus: %d", len(rows))
    return len(rows)
