from __future__ import annotations

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import connection as PGConnection

from config import Settings


def get_connection(settings: Settings) -> PGConnection:
    conn = psycopg2.connect(
        user=settings.db_user,
        password=settings.db_password,
        host=settings.db_host,
        dbname=settings.db_name,
        port=settings.db_port,
        application_name="zbx-alert-relay-uk",
        connect_timeout=10,
    )
    # search_path задаётся отдельным SET, а не параметром startup-пакета
    # (options=-c ...) — за managed-Postgres часто стоит пулер (PgBouncer
    # и т.п.), который отклоняет нестандартные startup-параметры соединения
    # ("unsupported startup parameter in options"). pyrus_sites живёт в
    # схеме settings.db_schema (registry-pyrus-tasks создаёт её через
    # DB_SCHEMA) — тот же search_path, чтобы безсхемный SELECT в
    # load_sites() резолвился туда же, а не в public.
    with conn.cursor() as cur:
        cur.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(settings.db_schema)))
    conn.commit()
    return conn
