"""
scheduler.py — точка входа.

Запуск:
    python scheduler.py
"""

from __future__ import annotations

import asyncio
import logging
import sys

from apscheduler.schedulers.asyncio import AsyncIOScheduler

import pipeline
from bot import Bot
from config import Settings
from junos import JunosApi
from models import IncidentReport
from notifier import build_notification, create_bot, send_notification
from report import print_incident_reports
from zabbix import ZabbixApi

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("pyzabbix").setLevel(logging.WARNING)

def _sync_pipeline(settings: Settings) -> list[IncidentReport]:
    with ZabbixApi(settings.zabbix_config()) as zapi:
        junos = JunosApi(settings)
        return pipeline.run(zapi, junos)


async def check_rpm(settings: Settings, bot: Bot) -> None:
    logger.debug("▶ Запуск RPM-проверки")
    try:
        reports = await asyncio.to_thread(_sync_pipeline, settings)
    except Exception as exc:
        logger.error("Ошибка выполнения pipeline: %s", exc)
        return

    if not reports:
        logger.debug("Активных RPM-проблем не найдено.")
        return

    print_incident_reports(reports)

    chat_id = settings.bot_chat_id
    if not chat_id:
        logger.warning("BOT_CHAT_ID не задан — уведомления не отправляются.")
        return

    for report in reports:
        msg = build_notification(report)
        if msg:
            await send_notification(bot, chat_id, msg)

    logger.info("◀ RPM-проверка завершена (%d инцидент(ов))", len(reports))


async def main() -> None:
    settings = Settings()

    if not settings.bot_token:
        logger.error("BOT_TOKEN не задан в .env — уведомления отправляться не будут.")

    bot = create_bot(
        token=settings.bot_token,
        api_url=settings.bot_url,
        proxy=settings.bot_proxy,
    )

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        check_rpm,
        trigger="interval",
        seconds=10,
        args=[settings, bot],
        id="rpm_check",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Планировщик запущен. Интервал: 5 минут. Нажмите Ctrl+C для остановки.")

    await check_rpm(settings, bot)  # немедленный первый запуск

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Получен сигнал остановки.")
    finally:
        scheduler.shutdown(wait=False)
        await bot.close()
        logger.info("Планировщик остановлен.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
