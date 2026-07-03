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
from emulator import load_emulated_apis
from junos import JunosApi
from mailer import send_provider_notification
from matcher import RegistryMatcher
from models import IncidentReport
from notifier import build_notification, create_bot, send_notification
from pyrus import PyrusClient, PyrusSiteParser
from report import print_incident_reports
from zabbix import ZabbixApi

# Временно: путь к JSON-файлу с эмулированными алертами и данными
# оборудования (схема — см. emulator.py). Если задан — check_rpm берёт
# данные ИЗ ФАЙЛА вместо реального Zabbix/Junos; файл перечитывается на
# каждом цикле, так что правки применяются без перезапуска процесса. Бот
# и чат при этом настоящие — сообщения реально уходят получателю. Реестр
# Pyrus — из файла (ключ "pyrus_sites"), либо, если его там нет, реальный,
# загруженный при старте. Пусто/None — обычный боевой режим.
# Готовые случаи: tests/dev_alerts/dev_alerts_1.json … dev_alerts_7.json
# (1 деградация, 2 перегрузка, 3 обрыв 100%, 4 SSH недоступен,
#  5 потери IPSEC, 6 ложное срабатывание, 7 игнорируемый inet).
EMULATOR_FIXTURE: str | None = "tests/dev_alerts/dev_alerts_1.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("pyzabbix").setLevel(logging.WARNING)


class SentRegistry:
    """
    Отметки об уже отправленных в чат инцидентах (ключ — eventid Zabbix).

    Планировщик крутится каждые 10 секунд; без этих отметок один и тот же
    активный инцидент слался бы в чат на каждом цикле. Отметка ставится
    после отправки и снимается, когда инцидент пропадает из активных —
    тогда при повторном возникновении (новый eventid) сообщение придёт снова.
    """

    def __init__(self) -> None:
        self._sent: set[str] = set()

    def was_sent(self, eventid: str) -> bool:
        return eventid in self._sent

    def mark(self, eventid: str) -> None:
        self._sent.add(eventid)

    def retain_active(self, active_ids: set[str]) -> None:
        self._sent &= active_ids


def _build_matcher(settings: Settings) -> RegistryMatcher | None:
    """Загружает реестр каналов связи из Pyrus и строит matcher по IP."""
    if not (settings.pyrus_login and settings.pyrus_token and settings.pyrus_form_id):
        logger.warning(
            "Pyrus не сконфигурирован (PYRUS_LOGIN/PYRUS_TOKEN/PYRUS_FORM_ID) — "
            "сопоставление задач отключено, договор в сообщениях будет «—».",
        )
        return None
    try:
        client = PyrusClient()
        tasks  = client.get_registry(settings.pyrus_form_id, settings.pyrus_login, settings.pyrus_token)
        sites  = PyrusSiteParser.parse_many(tasks)
        matcher = RegistryMatcher(sites)
        logger.info("Реестр Pyrus загружен: %d задач", len(sites))
        return matcher
    except Exception as exc:
        logger.error("Не удалось загрузить реестр Pyrus: %s", exc)
        return None


def _sync_pipeline(settings: Settings, matcher: RegistryMatcher | None) -> list[IncidentReport]:
    if EMULATOR_FIXTURE:
        zapi, junos, fixture_matcher = load_emulated_apis(EMULATOR_FIXTURE)
        return pipeline.run(zapi, junos, fixture_matcher if fixture_matcher is not None else matcher)
    with ZabbixApi(settings.zabbix_config()) as zapi:
        junos = JunosApi(settings)
        return pipeline.run(zapi, junos, matcher)


async def check_rpm(
    settings: Settings,
    bot:      Bot,
    matcher:  RegistryMatcher | None,
    sent:     SentRegistry,
) -> None:
    logger.debug("▶ Запуск RPM-проверки")
    try:
        reports = await asyncio.to_thread(_sync_pipeline, settings, matcher)
    except Exception as exc:
        logger.error("Ошибка выполнения pipeline: %s", exc)
        return

    if not reports:
        logger.debug("Активных RPM-проблем не найдено.")
        sent.retain_active(set())
        return

    print_incident_reports(reports)

    chat_id = settings.bot_chat_id
    if not chat_id:
        logger.warning("BOT_CHAT_ID не задан — уведомления не отправляются.")
        return

    new_msgs = 0
    for report in reports:
        msg = build_notification(report)
        if not msg:
            continue
        eventid = report.problem.eventid
        if sent.was_sent(eventid):
            logger.debug("Инцидент %s уже отправлен ранее — пропуск", eventid)
            continue
        await send_notification(bot, chat_id, msg)
        # Письмо оператору напрямую (инертно, пока не заданы MAIL_* в config).
        await asyncio.to_thread(send_provider_notification, settings, report)
        sent.mark(eventid)
        new_msgs += 1

    # Снимаем отметки с инцидентов, которых больше нет среди активных.
    sent.retain_active({r.problem.eventid for r in reports})

    logger.info("◀ RPM-проверка завершена (%d инцидент(ов), новых сообщений: %d)",
                len(reports), new_msgs)


async def main() -> None:
    settings = Settings()

    if EMULATOR_FIXTURE:
        logger.warning(
            "⚠ ЭМУЛЯТОР АЛЕРТОВ АКТИВЕН (EMULATOR_FIXTURE=%s): данные берутся из файла, "
            "реальные Zabbix/Junos не используются. Бот шлёт сообщения в реальный чат.",
            EMULATOR_FIXTURE,
        )

    if not settings.bot_token:
        logger.error("BOT_TOKEN не задан в .env — уведомления отправляться не будут.")

    bot = create_bot(
        token=settings.bot_token,
        api_url=settings.bot_url,
        proxy=settings.bot_proxy,
    )

    # Реестр Pyrus загружается один раз при старте.
    matcher = _build_matcher(settings)

    # Отметки об отправленных инцидентах живут на всё время работы процесса.
    sent = SentRegistry()

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        check_rpm,
        trigger="interval",
        seconds=10,
        args=[settings, bot, matcher, sent],
        id="rpm_check",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Планировщик запущен. Интервал: 5 минут. Нажмите Ctrl+C для остановки.")

    await check_rpm(settings, bot, matcher, sent)  # немедленный первый запуск

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Получен сигнал остановки.")
    finally:
        scheduler.shutdown(wait=False)
        logger.info("Планировщик остановлен.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
