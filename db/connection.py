from __future__ import annotations

import psycopg2
from psycopg2.extensions import connection as PGConnection

from config import Settings


def get_connection(settings: Settings) -> PGConnection:
    return psycopg2.connect(
        user=settings.db_user,
        password=settings.db_password,
        host=settings.db_host,
        dbname=settings.db_name,
        port=settings.db_port,
        application_name="zbx-alert-relay-uk",
        connect_timeout=10,
        # pyrus_sites живёт в схеме settings.db_schema (registry-pyrus-tasks
        # создаёт её через DB_SCHEMA) — тот же search_path, чтобы безсхемный
        # SELECT в load_sites() резолвился туда же, а не в public.
        options=f"-c search_path={settings.db_schema}",
    )
