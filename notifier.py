from __future__ import annotations

import logging

from bot import Bot
from const import CHANNEL_UTIL_THRESHOLD_PCT, PING_COUNT, get_cod_by_name
from models import IncidentDecision, IncidentReport

logger = logging.getLogger(__name__)


def create_bot(token: str, api_url: str, proxy: str) -> Bot:
    return Bot(
        token=token,
        api_url_base=api_url or None,
        proxy_url=proxy or None,
    )


async def send_notification(bot: Bot, chat_id: str, text: str) -> None:
    try:
        await bot.send_text(chat_id=chat_id, text=text)
        logger.info("Уведомление отправлено в chat_id=%s", chat_id)
    except Exception as exc:
        logger.error("Ошибка отправки уведомления: %s", exc)


def _contract(report: IncidentReport, cod) -> str:
    """Номер договора: сначала из канала Pyrus, затем из COD, иначе прочерк."""
    channel = report.pyrus_channel
    if channel and channel.contract:
        logger.debug("Договор для host=%s: %r (из канала Pyrus)",
                      report.problem.host_name, channel.contract)
        return channel.contract
    if cod and cod.contract:
        logger.debug("Договор для host=%s: %r (из COD %s)",
                      report.problem.host_name, cod.contract, cod.name)
        return cod.contract
    logger.debug(
        "Договор для host=%s не определён (pyrus_channel=%s, cod=%s) — «—»",
        report.problem.host_name,
        "найден без договора" if channel else "не сопоставлен",
        cod.name if cod else None,
    )
    return "—"


def _operator(report: IncidentReport, cod) -> str:
    """Оператор связи: сначала провайдер сматченного канала Pyrus (реальный
    ISP, в т.ч. для интернет-каналов), затем провайдер из триггера, затем COD."""
    channel = report.pyrus_channel
    if channel and channel.provider:
        return channel.provider
    p = report.problem
    if p.provider:
        return p.provider
    if cod and cod.operator:
        return cod.operator
    return p.cod_name or "—"


def _service(report: IncidentReport) -> str:
    """Услуга канала (L2VPN/Интернет/Тёмное волокно/...) из Pyrus — не все
    каналы вообще L2-транспорт, поэтому в текстах сообщений подставляется
    реальная услуга, а не жёстко "L2VPN"."""
    ch = report.pyrus_channel
    if ch and ch.service:
        return ch.service
    return "L2VPN"


def _utilization_str(util_pct: float | None) -> str:
    if util_pct is None:
        return "данные недоступны"
    qualifier = (
        "превышает критический порог" if util_pct > CHANNEL_UTIL_THRESHOLD_PCT
        else "ниже критического порога"
    )
    return f"{util_pct:.0f}% ({qualifier})"


def format_degradation_message(report: IncidentReport) -> str:
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    operator = _operator(report, cod)
    contract = _contract(report, cod)
    address  = p.host_name or "—"
    service  = _service(report)

    loss_pct = _report_loss_pct(report)
    util_str = _utilization_str(report.utilization_pct)

    return (
        f"Зафиксирована деградация на канале связи {service}. "
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Идентификатор канала (номер договора): {contract}\n"
        f"3. Результаты проверки транспорта:\n"
        f"   - Потери ICMP: {loss_pct:.0f}%\n"
        f"4. Утилизация канала в пике за период инцидента: {util_str}"
    )


def format_channel_down_message(report: IncidentReport) -> str:
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    operator = _operator(report, cod)
    contract = _contract(report, cod)
    address  = p.host_name or "—"
    service  = _service(report)

    return (
        f"Канал связи {service} полностью недоступен (потери ICMP 100%).\n"
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Идентификатор канала (номер договора): {contract}\n"
        f"3. Результаты проверки транспорта:\n"
        f"   - Потери ICMP: 100% (канал недоступен)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# ШАБЛОНЫ ДЛЯ SITE-АЛЕРТОВ («Потери до <имя площадки>»).
# Пока текст идентичен канальным алертам — правьте строки ниже под свои нужды,
# на канальные сообщения (format_*_message выше) это не повлияет.
# ─────────────────────────────────────────────────────────────────────────────

def format_site_degradation_message(report: IncidentReport) -> str:
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    operator = _operator(report, cod)
    contract = _contract(report, cod)
    address  = p.host_name or "—"
    service  = _service(report)

    loss_pct = _report_loss_pct(report)
    util_str = _utilization_str(report.utilization_pct)

    return (
        f"Зафиксирована деградация на канале связи {service}. "
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Идентификатор канала (номер договора): {contract}\n"
        f"3. Результаты проверки транспорта:\n"
        f"   - Потери ICMP: {loss_pct:.0f}%\n"
        f"4. Утилизация канала в пике за период инцидента: {util_str}"
    )


def format_site_channel_down_message(report: IncidentReport) -> str:
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    operator = _operator(report, cod)
    contract = _contract(report, cod)
    address  = p.host_name or "—"
    service  = _service(report)

    return (
        f"Канал связи {service} полностью недоступен (потери ICMP 100%).\n"
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Идентификатор канала (номер договора): {contract}\n"
        f"3. Результаты проверки транспорта:\n"
        f"   - Потери ICMP: 100% (канал недоступен)"
    )


def format_reserve_unavailable_message(report: IncidentReport) -> str:
    """
    Эскалация для site-алерта: основной канал не в порядке, а переключение
    на резерв не удалось выполнить, т.к. резерв сам недоступен — в отличие
    от обычной деградации/обрыва, здесь называются ОБА канала сразу.
    """
    p = report.problem
    address = p.host_name or "—"

    primary = report.primary_channel
    reserve = report.pyrus_channel
    primary_operator = (primary.provider if primary and primary.provider else None) or "—"
    primary_contract = (primary.contract if primary and primary.contract else None) or "—"
    primary_service  = (primary.service if primary and primary.service else None) or "L2VPN"
    reserve_operator = (reserve.provider if reserve and reserve.provider else None) or "—"
    reserve_contract = (reserve.contract if reserve and reserve.contract else None) or "—"
    reserve_service  = (reserve.service if reserve and reserve.service else None) or "L2VPN"

    return (
        f"Зафиксирована недоступность ОСНОВНОГО И РЕЗЕРВНОГО каналов связи "
        f"площадки. Автоматическое переключение на резерв невозможно — резервный "
        f"канал сам недоступен. Требуется ручное вмешательство.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Основной канал: услуга {primary_service}, оператор {primary_operator}, договор {primary_contract}\n"
        f"3. Резервный канал: услуга {reserve_service}, оператор {reserve_operator}, договор {reserve_contract}"
    )


def build_notification(report: IncidentReport) -> str | None:
    d = report.decision
    if d == IncidentDecision.RESERVE_UNAVAILABLE:
        return format_reserve_unavailable_message(report)
    if report.problem.site_alert:
        if d == IncidentDecision.CHANNEL_DOWN:
            return format_site_channel_down_message(report)
        if d in (IncidentDecision.DEGRADED_CHANNEL, IncidentDecision.HIGH_UTILIZATION):
            return format_site_degradation_message(report)
        return None
    if d == IncidentDecision.CHANNEL_DOWN:
        return format_channel_down_message(report)
    if d in (IncidentDecision.DEGRADED_CHANNEL, IncidentDecision.HIGH_UTILIZATION):
        return format_degradation_message(report)
    return None


def _avg_loss_pct(results, ping_count: int = PING_COUNT) -> float:
    if not results or ping_count <= 0:
        return 0.0
    total = sum(r.loss or 0 for r in results)
    return total / (ping_count * len(results)) * 100


def _report_loss_pct(report: IncidentReport, ping_count: int = PING_COUNT) -> float:
    """
    Site-алерт с несколькими L2VPN-каналами площадки: сообщение адресовано
    оператору report.pyrus_channel (выбранному по report.degraded_link) —
    потери в тексте должны быть про этот конкретный канал, а не усреднены
    со здоровыми соседними (иначе цифра разойдётся с тем, о чём письмо).
    Для канальных алертов degraded_link не заполняется — считаем как раньше.
    """
    if report.degraded_link is not None:
        return (report.degraded_link.loss or 0) / ping_count * 100 if ping_count > 0 else 0.0
    return _avg_loss_pct(report.ping_results, ping_count)
