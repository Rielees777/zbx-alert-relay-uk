"""
scheduler.py — точка входа.

Запуск:
    python scheduler.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time

from apscheduler.schedulers.asyncio import AsyncIOScheduler

import pipeline
from bot import Bot
from config import Settings
from const import CHECK_INTERVAL_MINUTES, MAX_ALERT_AGE_SEC, RESEND_AFTER_SEC
from db import get_connection, load_sites
from emulator import load_emulated_apis
from junos import JunosApi
from mailer import send_provider_notification
from matcher import RegistryMatcher
from models import IncidentReport
from notifier import build_notification, create_bot, send_notification
from pyrus_sync import sync_registry
from report import print_incident_reports
from zabbix import ZabbixApi

# Временно: путь к JSON-файлу с эмулированными алертами и данными
# оборудования (схема — см. emulator.py). Если задан — check_rpm берёт
# данные ИЗ ФАЙЛА вместо реального Zabbix/Junos; файл перечитывается на
# каждом цикле, так что правки применяются без перезапуска процесса. Бот
# и чат при этом настоящие — сообщения реально уходят получателю. Реестр
# Pyrus — из файла (ключ "pyrus_sites"), либо, если его там нет, реальный,
# загруженный при старте. Пусто/None — обычный боевой режим.
# Готовые случаи: tests/dev_alerts/dev_alerts_1.json … dev_alerts_8.json
# (1 деградация, 2 перегрузка, 3 обрыв 100%, 4 SSH недоступен,
#  5 потери IPSEC, 6 ложное срабатывание, 7 игнорируемый inet, 8 site-алерт).
# БОЕВОЙ РЕЖИМ = None. Для локального теста раскомментируйте строку с файлом.
EMULATOR_FIXTURE: str | None = None
# EMULATOR_FIXTURE = "tests/dev_alerts/dev_alerts_1.json"

# Уровень логирования: LOG_LEVEL=DEBUG в .env/окружении включает подробный
# разбор сопоставления Pyrus (matcher/find_channel_by_trigger/_attach_pyrus/
# _contract) — полезно, когда в сообщении/письме не появляется договор.
_LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, _LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("pyzabbix").setLevel(logging.WARNING)


class SentRegistry:
    """
    Отметки об уже отработанных инцидентах (ключ — eventid Zabbix).

    Отметка ставится после отправки уведомлений (чат + письмо оператору);
    с этого момента на инцидент больше не реагируем вовсе — он отсекается
    на входе пайплайна (до junos-проверок). Повторное возникновение той же
    проблемы Zabbix регистрирует новым eventid — такой инцидент будет
    отработан как новый. Старые отметки чистятся по TTL, чтобы реестр не
    рос бесконечно (события старше окна выборки в него всё равно не попадают).
    """

    def __init__(self, ttl_sec: int) -> None:
        self._sent: dict[str, float] = {}
        self._ttl = ttl_sec

    def mark(self, eventid: str) -> None:
        self._sent[eventid] = time.time()

    def purge(self) -> None:
        cutoff = time.time() - self._ttl
        self._sent = {eid: ts for eid, ts in self._sent.items() if ts >= cutoff}

    def snapshot(self) -> frozenset[str]:
        return frozenset(self._sent)

    def should_process(self, eventid: str, started: int, now: float | None = None) -> bool:
        """
        ДОРМАНТНЫЙ хелпер (в боевом пути пока НЕ вызывается — инструкция
        подключения в check_rpm). Единое решение «обрабатывать ли алерт» с
        учётом верхней границы возраста и повторной отправки:

          • инцидент уже отработан (есть отметка): обрабатываем повторно ТОЛЬКО
            если с последней отправки прошло >= RESEND_AFTER_SEC (алерт всё ещё
            открыт — иначе Zabbix его бы закрыл и он сюда не попал). На возраст
            при этом НЕ смотрим — это напоминание о зависшей проблеме;
          • инцидент ещё не отработан (отметки нет): обрабатываем, если он не
            старше MAX_ALERT_AGE_SEC. Более старый первичный алерт
            («залежавшийся») пропускаем.

        started — problem.started (Zabbix clock, unix-время начала проблемы).

        ВНИМАНИЕ при подключении: TTL реестра (ttl_sec) должен быть НЕ меньше
        RESEND_AFTER_SEC (лучше с запасом), иначе отметка отработанного
        инцидента будет вычищена purge() раньше, чем наступит повторная
        отправка, и старый алерт ошибочно сочтётся первичным и будет отсечён
        по верхней границе возраста.
        """
        now = time.time() if now is None else now
        marked = self._sent.get(eventid)
        if marked is not None:                       # уже уведомляли
            return (now - marked) >= RESEND_AFTER_SEC
        if MAX_ALERT_AGE_SEC is not None and (now - started) > MAX_ALERT_AGE_SEC:
            return False                             # первичный, но «залежавшийся»
        return True


class MatcherRef:
    """Изменяемая ссылка на текущий RegistryMatcher. check_rpm получает её
    один раз при старте планировщика; run_pyrus_sync подменяет .value после
    каждой успешной ежедневной синхронизации — без этого обновлённый реестр
    подхватывался бы только при перезапуске процесса."""

    def __init__(self, matcher: RegistryMatcher | None) -> None:
        self.value = matcher


def _build_matcher(settings: Settings) -> RegistryMatcher | None:
    """Загружает реестр каналов связи Pyrus из PostgreSQL (таблицу pyrus_sites
    наполняет сама ежедневная синхронизация, см. pyrus_sync.py) и строит
    matcher по IP."""
    try:
        conn = get_connection(settings)
        try:
            sites = load_sites(conn)
        finally:
            conn.close()
        matcher = RegistryMatcher(sites)
        logger.info("Реестр Pyrus загружен из БД: %d задач", len(sites))
        return matcher
    except Exception as exc:
        logger.error("Не удалось загрузить реестр Pyrus из БД (DB_*): %s", exc)
        return None


def _sync_pipeline(
    settings:        Settings,
    matcher:         RegistryMatcher | None,
    skip_eventids:   frozenset[str],
    process_decider=None,   # ДОРМАНТНО: None → боевое поведение (отсечка только
                            # по skip_eventids). Передайте sent.should_process,
                            # чтобы включить верхнюю границу возраста + повтор.
) -> list[IncidentReport]:
    if EMULATOR_FIXTURE:
        zapi, junos, fixture_matcher = load_emulated_apis(EMULATOR_FIXTURE)
        return pipeline.run(zapi, junos,
                            fixture_matcher if fixture_matcher is not None else matcher,
                            skip_eventids=skip_eventids, process_decider=process_decider)
    with ZabbixApi(settings.zabbix_config()) as zapi:
        junos = JunosApi(settings)
        return pipeline.run(zapi, junos, matcher, skip_eventids=skip_eventids,
                            process_decider=process_decider)


async def run_pyrus_sync(settings: Settings, matcher_ref: MatcherRef) -> None:
    """Ежедневная задача планировщика: тянет реестр из Pyrus в pyrus_sites
    и, если что-то сохранилось, перестраивает matcher на свежих данных —
    без этого обновление реестра подхватывалось бы только при рестарте."""
    logger.info("▶ Запуск ежедневной синхронизации реестра Pyrus")
    try:
        saved = await asyncio.to_thread(sync_registry, settings)
    except Exception as exc:
        logger.error("Синхронизация реестра Pyrus завершилась с ошибкой: %s", exc)
        return

    logger.info("◀ Синхронизация реестра Pyrus завершена: %d задач сохранено", saved)
    if not saved:
        return

    new_matcher = await asyncio.to_thread(_build_matcher, settings)
    if new_matcher is not None:
        matcher_ref.value = new_matcher


async def check_rpm(
    settings:    Settings,
    bot:         Bot,
    matcher_ref: MatcherRef,
    sent:        SentRegistry,
) -> None:
    logger.debug("▶ Запуск RPM-проверки")
    sent.purge()
    try:
        # Уже отработанные инциденты отсекаются на входе пайплайна —
        # для них не выполняются ни junos-проверки, ни уведомления.
        #
        # ── КАК ПОДКЛЮЧИТЬ верхнюю границу возраста + повторную отправку ──────
        # Сейчас выключено: действует только отсечка уже отработанных через
        # sent.snapshot(); MAX_ALERT_AGE_SEC/RESEND_AFTER_SEC в боевом пути не
        # применяются, повтор происходит неявно по TTL реестра. Чтобы включить:
        #   1) в main() создайте реестр с TTL не меньше RESEND_AFTER_SEC (с
        #      запасом), напр. SentRegistry(ttl_sec=RESEND_AFTER_SEC + 24*3600)
        #      — отметка обязана дожить до момента повторной отправки;
        #   2) замените вызов ниже на передачу предиката should_process:
        #        reports = await asyncio.to_thread(
        #            _sync_pipeline, settings, matcher_ref.value,
        #            sent.snapshot(), sent.should_process)
        #      (parameter process_decider уже проброшен в _sync_pipeline →
        #      pipeline.run → _collect_problems; когда он задан, заменяет собой
        #      отсечку по skip_eventids и учитывает возраст/повтор per-event).
        # ─────────────────────────────────────────────────────────────────────
        reports = await asyncio.to_thread(_sync_pipeline, settings, matcher_ref.value, sent.snapshot())
    except Exception as exc:
        logger.error("Ошибка выполнения pipeline: %s", exc)
        return

    if not reports:
        logger.debug("Активных RPM-проблем для обработки не найдено.")
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
        await send_notification(bot, chat_id, msg)
        # Письмо оператору напрямую (инертно, пока не заданы MAIL_* в config).
        await asyncio.to_thread(send_provider_notification, settings, report)
        # Инцидент отработан: сообщение мониторингу и письмо оператору
        # направлены — больше на этот eventid не реагируем.
        sent.mark(report.problem.eventid)
        new_msgs += 1

    logger.info("◀ RPM-проверка завершена (%d инцидент(ов), новых сообщений: %d)",
                len(reports), new_msgs)


async def main() -> None:
    settings = Settings()

    # LOG_LEVEL мог быть задан в .env (pydantic Settings), а не только как
    # переменную окружения процесса — basicConfig() при импорте видит только
    # последнюю. Перевыставляем уровень здесь, чтобы .env тоже работал.
    effective_level = settings.log_level.upper()
    logging.getLogger().setLevel(getattr(logging, effective_level, logging.INFO))
    logger.info("Уровень логирования: %s", effective_level)

    if EMULATOR_FIXTURE:
        logger.warning(
            "⚠ ЭМУЛЯТОР АЛЕРТОВ АКТИВЕН (EMULATOR_FIXTURE=%s): данные берутся из файла, "
            "реальные Zabbix/Junos не используются. Бот шлёт сообщения в реальный чат.",
            EMULATOR_FIXTURE,
        )

    if not settings.bot_token:
        logger.error("BOT_TOKEN не задан в .env — уведомления отправляться не будут.")

    if settings.mail_enabled:
        logger.info("Почта оператору включена: %s (ящик %s, запасной адрес %s)",
                    settings.mail_service_url, settings.mailbox,
                    settings.mail_to_default or "не задан")
    else:
        logger.warning("MAIL_SERVICE_URL не задан в .env — письма оператору отправляться не будут.")

    bot = create_bot(
        token=settings.bot_token,
        api_url=settings.bot_url,
        proxy=settings.bot_proxy,
    )

    if not settings.pyrus_configured:
        logger.warning(
            "Pyrus не сконфигурирован (PYRUS_LOGIN/PYRUS_TOKEN/PYRUS_FORM_ID) — "
            "ежедневная синхронизация реестра работать не будет.",
        )

    # Реестр Pyrus загружается один раз при старте (из БД, которую
    # наполняет ежедневная синхронизация ниже) и хранится за изменяемой
    # ссылкой, чтобы run_pyrus_sync мог подменить его на свежий без рестарта.
    matcher_ref = MatcherRef(_build_matcher(settings))

    # Отметки об отработанных инцидентах. eventid Zabbix уникальны и не
    # переиспользуются, поэтому TTL нужен только как гигиена памяти; он
    # обязан быть больше жизни самого долгого открытого алерта — иначе
    # незакрытый инцидент уведомлялся бы повторно после очистки отметки.
    sent = SentRegistry(ttl_sec=7 * 24 * 3600)

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        check_rpm,
        trigger="interval",
        minutes=CHECK_INTERVAL_MINUTES,
        args=[settings, bot, matcher_ref, sent],
        id="rpm_check",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.add_job(
        run_pyrus_sync,
        trigger="cron",
        hour=settings.pyrus_sync_hour,
        minute=settings.pyrus_sync_minute,
        args=[settings, matcher_ref],
        id="pyrus_registry_sync",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Планировщик запущен. RPM-проверка каждые %d минут, синхронизация "
        "реестра Pyrus ежедневно в %02d:%02d. Нажмите Ctrl+C для остановки.",
        CHECK_INTERVAL_MINUTES, settings.pyrus_sync_hour, settings.pyrus_sync_minute,
    )

    await check_rpm(settings, bot, matcher_ref, sent)  # немедленный первый запуск

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
