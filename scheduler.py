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
from const import (
    CHECK_INTERVAL_MINUTES,
    FLAP_ALERT_THRESHOLD,
    FLAP_WINDOW_SEC,
    MAX_ALERT_AGE_SEC,
    RESEND_AFTER_SEC,
)
from db import get_connection, load_sites
from emulator import load_emulated_apis
from junos import JunosApi
from mailer import is_provider_mail_expected, send_provider_notification
from matcher import RegistryMatcher
from models import IncidentDecision, IncidentReport
from notifier import build_flapping_message, build_notification, create_bot, send_notification
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


def channel_flap_key(problem) -> str:
    """Ключ канала для антиспам-окна флапа: узел + идентификатор канала из
    триггера (channel_spec). Для site-алертов channel_spec может отсутствовать
    — тогда ключуемся по имени площадки, чтобы флапы одной площадки собрались
    вместе."""
    spec = problem.channel_spec or (f"site:{problem.host_name or ''}"
                                    if problem.site_alert else "?")
    return f"{problem.host_tech}|{spec}"


class ChannelFlapRegistry:
    """
    Антиспам флапающих каналов. После того как по каналу направлено обращение
    оператору (register_sent), повторные проблемы того же канала в течение
    `window_sec` НЕ порождают новых писем/сообщений — они считаются
    (record_repeat); когда счётчик пришедших алертов превысит `threshold`,
    record_repeat один раз возвращает True — сигнал отправить в чат сообщение
    о нестабильном канале. Ключ — channel_flap_key(problem). Состояние
    in-memory (как у SentRegistry): при рестарте окна сбрасываются.
    """

    def __init__(self, window_sec: int, threshold: int) -> None:
        self._window = window_sec
        self._threshold = threshold
        # key -> {"start": float, "count": int, "flap_sent": bool}
        self._state: dict[str, dict] = {}

    def purge(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._state = {
            k: st for k, st in self._state.items()
            if now - st["start"] < self._window
        }

    def within_window(self, key: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        st = self._state.get(key)
        return st is not None and (now - st["start"]) < self._window

    def register_sent(self, key: str, now: float | None = None) -> None:
        """Открыть новое окно (по каналу только что направлено письмо)."""
        now = time.time() if now is None else now
        self._state[key] = {"start": now, "count": 1, "flap_sent": False}

    def record_repeat(self, key: str) -> tuple[int, bool]:
        """Учесть повторный алерт в открытом окне. Возвращает (счётчик,
        нужно_ли_отправить_сообщение_о_флапе) — второй True ровно один раз,
        когда счётчик впервые превышает threshold."""
        st = self._state[key]
        st["count"] += 1
        emit = st["count"] > self._threshold and not st["flap_sent"]
        if emit:
            st["flap_sent"] = True
        return st["count"], emit


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
    flaps:       ChannelFlapRegistry,
) -> None:
    logger.debug("▶ Запуск RPM-проверки")
    sent.purge()
    flaps.purge()
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

    new_msgs  = 0
    flap_msgs = 0
    for report in reports:
        # Есть ли вообще что сообщать по этому решению (перегрузка/деградация/
        # обрыв/эскалация). Если нет (ложное срабатывание, IPSEC, ошибка) —
        # инцидент не уведомляется и в антиспам-окно флапа не попадает.
        if build_notification(report) is None:
            continue

        key = channel_flap_key(report.problem)

        # Эскалация RESERVE_UNAVAILABLE исключена из флап-подавления: недоступны
        # ОБА канала (нужно ручное вмешательство), и в сценарии эскалации она
        # приходит тем же циклом и с тем же ключом канала, что и основной отчёт
        # — тот успел бы открыть окно и заглушить эскалацию. Такое событие
        # всегда отправляем и в антиспам-окно не заводим.
        is_escalation = report.decision == IncidentDecision.RESERVE_UNAVAILABLE

        # Антиспам флапа: по каналу уже направлено обращение оператору и с тех
        # пор не прошли сутки — новых писем/сообщений не создаём, только считаем
        # эпизоды; при превышении порога один раз шлём в чат сообщение о
        # нестабильном канале.
        if not is_escalation and flaps.within_window(key):
            count, emit_flap = flaps.record_repeat(key)
            if emit_flap:
                await send_notification(bot, chat_id, build_flapping_message(
                    report, count, window_hours=FLAP_WINDOW_SEC // 3600))
                flap_msgs += 1
                logger.info("Канал %s флапает: %d эпизодов за окно — сообщение о "
                            "нестабильности отправлено", key, count)
            else:
                logger.info("Канал %s: повторный алерт в антиспам-окне (эпизод "
                            "%d) — письмо/сообщение подавлены", key, count)
            # Тот же eventid не должен считаться повторно на каждом цикле, пока
            # проблема открыта — помечаем как отработанный.
            sent.mark(report.problem.eventid)
            continue

        # Первичная реакция по каналу: сначала письмо оператору (чтобы в
        # сообщение мониторингу подставить факт его отправки), затем чат.
        email_sent: bool | None = None
        if is_provider_mail_expected(settings, report):
            email_sent = await asyncio.to_thread(send_provider_notification, settings, report)

        msg = build_notification(report, provider_email_sent=email_sent)
        await send_notification(bot, chat_id, msg)

        # Окно антиспама открываем только если письмо оператору реально ушло —
        # именно оно «якорит» сутки подавления повторов (см. требование).
        # Эскалацию в окно не заводим, чтобы она не сбрасывала счётчик флапа
        # основного канала (ключ у них общий).
        if email_sent and not is_escalation:
            flaps.register_sent(key)

        # Инцидент отработан: больше на этот eventid не реагируем.
        sent.mark(report.problem.eventid)
        new_msgs += 1

    logger.info("◀ RPM-проверка завершена (%d инцидент(ов), новых сообщений: %d, "
                "сообщений о флапе: %d)", len(reports), new_msgs, flap_msgs)


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

    # Антиспам флапающих каналов: после письма оператору повторные проблемы
    # того же канала за сутки подавляются и считаются; при > FLAP_ALERT_THRESHOLD
    # эпизодах — одно сообщение о нестабильном канале в чат (см. check_rpm).
    flaps = ChannelFlapRegistry(window_sec=FLAP_WINDOW_SEC, threshold=FLAP_ALERT_THRESHOLD)

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        check_rpm,
        trigger="interval",
        minutes=CHECK_INTERVAL_MINUTES,
        args=[settings, bot, matcher_ref, sent, flaps],
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

    await check_rpm(settings, bot, matcher_ref, sent, flaps)  # немедленный первый запуск

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
