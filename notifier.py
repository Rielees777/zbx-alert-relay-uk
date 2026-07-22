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


def _channel_id(report: IncidentReport) -> str:
    """ID канала из реестра Pyrus (ChannelInfo.channel_id) — идентификатор,
    по которому оператор находит канал быстрее, чем по номеру договора.
    «—», если канал не сопоставлен или ID в реестре не указан."""
    ch = report.pyrus_channel
    return ch.channel_id if ch and ch.channel_id else "—"


def _bandwidth_mbps(report: IncidentReport) -> str | None:
    """Номинальная полоса канала из реестра Pyrus (ChannelInfo.bandwidth,
    в Кбит/с) в человекочитаемом виде «N Мбит/с». База конверсии — ÷1024
    (76800 Кбит/с → 75 Мбит/с). None, если ширина в реестре не указана —
    тогда строку про полосу в сообщение/письмо не добавляем."""
    ch = report.pyrus_channel
    if not ch or not ch.bandwidth:
        return None
    mbps = ch.bandwidth / 1024
    text = f"{mbps:.0f}" if abs(mbps - round(mbps)) < 0.05 else f"{mbps:.1f}"
    return f"{text} Мбит/с"


def _problem_interface_desc(report: IncidentReport) -> str | None:
    """Интерфейс с проблемой и его описание — для сообщения мониторингу, чтобы
    дежурный сразу видел, где именно обнаружены потери. Берём degraded_link
    (site-алерт, выбранный «худший» канал площадки), иначе — проблемный (с
    потерями) элемент ping_results, иначе первый из них. None, если пинга не
    было вовсе (напр. 100% по триггеру или узел недоступен по управлению)."""
    link = report.degraded_link
    if link is None:
        results = report.ping_results or []
        lossy = [r for r in results if r.has_loss]
        candidates = lossy or results
        link = candidates[0] if candidates else None
    if link is None:
        return None
    desc  = (link.description or "").strip()
    iface = (link.interface or "").strip()
    if desc and iface:
        return f'{iface} — «{desc}»'
    return desc or iface or None


def _email_status_line(provider_email_sent: bool | None) -> str | None:
    """Строка о факте отправки письма оператору для сообщения мониторингу.
    None → письмо по этому инциденту не предполагалось (напр. перегрузка) —
    строку не добавляем, чтобы не путать с реальной неудачей отправки."""
    if provider_email_sent is None:
        return None
    if provider_email_sent:
        return "Обращение оператору связи направлено (email)."
    return "Обращение оператору связи НЕ направлено — ошибка отправки (см. журнал)."


def _numbered(items: list[str]) -> str:
    """Нумерует пункты диагностики. Пункт может содержать переносы строк
    (напр. блок «Результаты проверки транспорта» с подпунктом) — нумеруется
    только первая строка пункта."""
    return "\n".join(f"{i}. {t}" for i, t in enumerate(items, 1))


def _utilization_str(util_pct: float | None) -> str:
    if util_pct is None:
        return "данные недоступны"
    qualifier = (
        "превышает критический порог" if util_pct > CHANNEL_UTIL_THRESHOLD_PCT
        else "ниже критического порога"
    )
    return f"{util_pct:.0f}% ({qualifier})"


def _degradation_items(report: IncidentReport) -> list[str]:
    """Пункты диагностики для сообщений о деградации (канальных и site).
    ID канала и договор — разными строками; интерфейс с проблемой добавляется,
    только если пинг вообще был."""
    cod = get_cod_by_name(report.problem.cod_name)
    items = [
        f"Адрес площадки: {report.problem.host_name or '—'}",
        f"Идентификатор канала: {_channel_id(report)}",
        f"Номер договора: {_contract(report, cod)}",
    ]
    bw = _bandwidth_mbps(report)
    if bw:
        items.append(f"Полоса канала: {bw}")
    iface = _problem_interface_desc(report)
    if iface:
        items.append(f"Интерфейс с проблемой: {iface}")
    items.append(
        f"Результаты проверки транспорта:\n"
        f"   - Потери ICMP: {_report_loss_pct(report):.0f}%"
    )
    items.append(
        f"Утилизация канала в пике за период инцидента: "
        f"{_utilization_str(report.utilization_pct)}"
    )
    return items


def _channel_down_items(report: IncidentReport) -> list[str]:
    """Пункты диагностики для сообщений о полной недоступности канала."""
    cod = get_cod_by_name(report.problem.cod_name)
    items = [
        f"Адрес площадки: {report.problem.host_name or '—'}",
        f"Идентификатор канала: {_channel_id(report)}",
        f"Номер договора: {_contract(report, cod)}",
    ]
    bw = _bandwidth_mbps(report)
    if bw:
        items.append(f"Полоса канала: {bw}")
    iface = _problem_interface_desc(report)
    if iface:
        items.append(f"Интерфейс с проблемой: {iface}")
    items.append("Результаты проверки транспорта:\n   - Потери ICMP: 100% (канал недоступен)")
    return items


def _with_email_status(body: str, provider_email_sent: bool | None) -> str:
    line = _email_status_line(provider_email_sent)
    return f"{body}\n{line}" if line else body


def format_degradation_message(report: IncidentReport, provider_email_sent: bool | None = None) -> str:
    operator = _operator(report, get_cod_by_name(report.problem.cod_name))
    body = (
        f"Зафиксирована деградация на канале связи {_service(report)}. "
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        + _numbered(_degradation_items(report))
    )
    return _with_email_status(body, provider_email_sent)


def format_channel_down_message(report: IncidentReport, provider_email_sent: bool | None = None) -> str:
    operator = _operator(report, get_cod_by_name(report.problem.cod_name))
    body = (
        f"Канал связи {_service(report)} полностью недоступен (потери ICMP 100%).\n"
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        + _numbered(_channel_down_items(report))
    )
    return _with_email_status(body, provider_email_sent)


# ─────────────────────────────────────────────────────────────────────────────
# ШАБЛОНЫ ДЛЯ SITE-АЛЕРТОВ («Потери до <имя площадки>»).
# Пока текст идентичен канальным алертам — правьте строки ниже под свои нужды,
# на канальные сообщения (format_*_message выше) это не повлияет.
# ─────────────────────────────────────────────────────────────────────────────

def format_site_degradation_message(report: IncidentReport, provider_email_sent: bool | None = None) -> str:
    operator = _operator(report, get_cod_by_name(report.problem.cod_name))
    body = (
        f"Зафиксирована деградация на канале связи {_service(report)}. "
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        + _numbered(_degradation_items(report))
    )
    return _with_email_status(body, provider_email_sent)


def format_site_channel_down_message(report: IncidentReport, provider_email_sent: bool | None = None) -> str:
    operator = _operator(report, get_cod_by_name(report.problem.cod_name))
    body = (
        f"Канал связи {_service(report)} полностью недоступен (потери ICMP 100%).\n"
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        + _numbered(_channel_down_items(report))
    )
    return _with_email_status(body, provider_email_sent)


def format_reserve_unavailable_message(report: IncidentReport, provider_email_sent: bool | None = None) -> str:
    """
    Эскалация для site-алерта: основной канал не в порядке, а переключение
    на резерв не удалось выполнить, т.к. резерв сам недоступен — в отличие
    от обычной деградации/обрыва, здесь называются ОБА канала сразу.
    """
    p = report.problem
    address = p.host_name or "—"

    primary = report.primary_channel
    reserve = report.pyrus_channel
    primary_operator   = (primary.provider   if primary and primary.provider   else None) or "—"
    primary_contract   = (primary.contract   if primary and primary.contract   else None) or "—"
    primary_service    = (primary.service    if primary and primary.service    else None) or "L2VPN"
    primary_channel_id = (primary.channel_id if primary and primary.channel_id else None) or "—"
    reserve_operator   = (reserve.provider   if reserve and reserve.provider   else None) or "—"
    reserve_contract   = (reserve.contract   if reserve and reserve.contract   else None) or "—"
    reserve_service    = (reserve.service    if reserve and reserve.service    else None) or "L2VPN"
    reserve_channel_id = (reserve.channel_id if reserve and reserve.channel_id else None) or "—"

    body = (
        f"Зафиксирована недоступность ОСНОВНОГО И РЕЗЕРВНОГО каналов связи "
        f"площадки. Автоматическое переключение на резерв невозможно — резервный "
        f"канал сам недоступен. Требуется ручное вмешательство.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Основной канал: услуга {primary_service}, ID канала {primary_channel_id}, "
        f"оператор {primary_operator}, договор {primary_contract}\n"
        f"3. Резервный канал: услуга {reserve_service}, ID канала {reserve_channel_id}, "
        f"оператор {reserve_operator}, договор {reserve_contract}"
    )
    return _with_email_status(body, provider_email_sent)


def build_flapping_message(report: IncidentReport, count: int,
                           window_hours: int = 24) -> str:
    """
    Сообщение в чат мониторинга о нестабильном (флапающем) канале: по каналу
    уже направлено обращение оператору, но проблема повторяется — за окно
    накопилось `count` эпизодов потерь. Письмо оператору при этом повторно
    НЕ шлётся (антиспам), это только внутреннее уведомление об эскалации.
    """
    cod = get_cod_by_name(report.problem.cod_name)
    items = [
        f"Адрес площадки: {report.problem.host_name or '—'}",
        f"Идентификатор канала: {_channel_id(report)}",
        f"Номер договора: {_contract(report, cod)}",
        f"Оператор связи: {_operator(report, cod)}",
        f"Эпизодов потерь за последние {window_hours} ч: {count}",
    ]
    extra = []
    bw = _bandwidth_mbps(report)
    if bw:
        extra.append(f"Полоса канала: {bw}")
    iface = _problem_interface_desc(report)
    if iface:
        extra.append(f"Интерфейс с проблемой: {iface}")
    for offset, line in enumerate(extra):
        items.insert(4 + offset, line)
    return (
        f"⚠ Канал связи {_service(report)} нестабилен (флапает): периодические "
        f"потери с разными интервалами. Обращение оператору по каждому эпизоду "
        f"не создаётся (антиспам — письмо уже направлено ранее). Рекомендуется "
        f"эскалация: повторяющиеся потери указывают на нестабильность канала.\n"
        f"Диагностическая информация:\n"
        + _numbered(items)
    )


def build_notification(report: IncidentReport, provider_email_sent: bool | None = None) -> str | None:
    d = report.decision
    if d == IncidentDecision.RESERVE_UNAVAILABLE:
        return format_reserve_unavailable_message(report, provider_email_sent)
    if report.problem.site_alert:
        if d == IncidentDecision.CHANNEL_DOWN:
            return format_site_channel_down_message(report, provider_email_sent)
        if d in (IncidentDecision.DEGRADED_CHANNEL, IncidentDecision.HIGH_UTILIZATION):
            return format_site_degradation_message(report, provider_email_sent)
        return None
    if d == IncidentDecision.CHANNEL_DOWN:
        return format_channel_down_message(report, provider_email_sent)
    if d in (IncidentDecision.DEGRADED_CHANNEL, IncidentDecision.HIGH_UTILIZATION):
        return format_degradation_message(report, provider_email_sent)
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
