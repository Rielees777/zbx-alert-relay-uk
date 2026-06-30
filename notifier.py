from __future__ import annotations

import logging

from bot import Bot
from const import PING_COUNT, get_cod_by_name
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
        return channel.contract
    if cod and cod.contract:
        return cod.contract
    return "—"


def format_degradation_message(report: IncidentReport) -> str:
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    operator = p.provider or (cod.operator if cod and cod.operator else p.cod_name) or "—"
    contract = _contract(report, cod)
    address  = p.host_name or "—"

    loss_pct = _avg_loss_pct(report.ping_results)
    util_str = (
        f"{report.utilization_pct:.0f}% (ниже критического порога)"
        if report.utilization_pct is not None
        else "данные недоступны"
    )

    return (
        f"Зафиксирована деградация на канале связи L2VPN. "
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Идентификатор канала (номер договора): {contract}\n"
        f"3. Результаты проверки L2VPN-транспорта:\n"
        f"   - Потери ICMP: {loss_pct:.0f}%\n"
        f"4. Утилизация канала в пике за период инцидента: {util_str}"
    )


def format_channel_down_message(report: IncidentReport) -> str:
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    operator = p.provider or (cod.operator if cod and cod.operator else p.cod_name) or "—"
    contract = _contract(report, cod)
    address  = p.host_name or "—"

    return (
        f"Канал связи L2VPN полностью недоступен (потери ICMP 100%).\n"
        f"Прошу сформировать и направить обращение оператору связи {operator} "
        f"для проверки и устранения проблемы.\n"
        f"Диагностическая информация:\n"
        f"1. Адрес площадки: {address}\n"
        f"2. Идентификатор канала (номер договора): {contract}\n"
        f"3. Результаты проверки L2VPN-транспорта:\n"
        f"   - Потери ICMP: 100% (канал недоступен)"
    )


def build_notification(report: IncidentReport) -> str | None:
    d = report.decision
    if d == IncidentDecision.CHANNEL_DOWN:
        return format_channel_down_message(report)
    if d == IncidentDecision.DEGRADED_CHANNEL:
        return format_degradation_message(report)
    return None


def _avg_loss_pct(results, ping_count: int = PING_COUNT) -> float:
    if not results or ping_count <= 0:
        return 0.0
    total = sum(r.loss or 0 for r in results)
    return total / (ping_count * len(results)) * 100
