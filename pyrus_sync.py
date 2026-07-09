from __future__ import annotations

import logging

from config import Settings
from db import get_connection
from db_write import init_schema, sync_sites
from pyrus import PyrusClient, PyrusSiteParser

logger = logging.getLogger(__name__)


def sync_registry(settings: Settings) -> int:
    """Забирает реестр каналов связи из Pyrus, парсит его через модели
    данных (models.PyrusSite/ChannelInfo) и выгружает в pyrus_sites.
    Возвращает число сохранённых задач, 0 — если Pyrus не сконфигурирован."""
    if not settings.pyrus_configured:
        logger.warning(
            "Pyrus не сконфигурирован (PYRUS_LOGIN/PYRUS_TOKEN/PYRUS_FORM_ID) — "
            "синхронизация реестра пропущена.",
        )
        return 0

    client = PyrusClient()
    tasks  = client.get_registry(settings.pyrus_form_id, settings.pyrus_login, settings.pyrus_token)
    sites  = PyrusSiteParser.parse_many(tasks, uk_only=settings.pyrus_uk_only)
    logger.info("Реестр Pyrus получен: %d задач", len(sites))

    conn = get_connection(settings)
    try:
        init_schema(conn, settings.db_schema)
        return sync_sites(conn, sites, batch_size=settings.db_batch_size)
    finally:
        conn.close()
