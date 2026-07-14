"""
mailer.py — отправка обращений оператору связи по email через mail-service
(HTTP REST API).

Дополняет уведомление в чат (notifier.py): по тому же инциденту формирует
письмо оператору по шаблону обращения и шлёт его на email провайдера через
внешний mail-service (POST {MAIL_SERVICE_URL}/emails/{MAILBOX}/send).

Адрес получателя: сначала PROVIDER_EMAILS[провайдер] (const.py), где провайдер
берётся из сматченного канала Pyrus; если провайдера там нет — на запасной
Settings.mail_to_default. Если ни того, ни другого — письмо не отправляется.

Инертен, пока не задан MAIL_SERVICE_URL (Settings.mail_enabled == False), —
так что подключение реального сервиса не требуется для остальной работы.
"""

from __future__ import annotations

import logging

import requests

from const import get_cod_by_name, get_provider_email
from models import IncidentDecision, IncidentReport
from notifier import _contract, _operator, _report_loss_pct
from providers import extract_email

logger = logging.getLogger(__name__)


def _address(report: IncidentReport) -> str:
    site = report.pyrus_site
    if site and site.address:
        return site.address
    return report.problem.host_name or "—"


def _service(report: IncidentReport) -> str:
    ch = report.pyrus_channel
    if ch and ch.service:
        return ch.service
    return "L2VPN"


def build_provider_email(report: IncidentReport) -> tuple[str, str]:
    """(subject, body) письма оператору по шаблону обращения.

    mail-service показывает тело как обычный текст (HTML-теги в нём
    выводятся буквально, не рендерятся) — тело обычный текст, строки
    разделены CRLF (\\r\\n, канонический перевод строки для email-тела
    по RFC 5322, в отличие от голого \\n).
    """
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    contract = _contract(report, cod)
    address  = _address(report)
    service  = _service(report)

    channel_down = report.decision == IncidentDecision.CHANNEL_DOWN
    if channel_down:
        loss_line = "        - Потери ICMP: 100% (канал недоступен)"
    else:
        loss_line = f"        - Потери ICMP: {_report_loss_pct(report):.0f}%"

    lines = [
        f"Здравствуйте! Наблюдаются проблема по адресу: {address}. Услуга {service}.",
        f"Договор: {contract}",
        f"Результаты проверки L2VPN-транспорта:",
        loss_line,
    ]
    # Канал полностью недоступен — утилизация тут ни при чём (нечего мерить),
    # строку с ней не добавляем.
    if not channel_down:
        util = report.utilization_pct
        lines.append(
            f"Утилизация канала в пике за период инцидента: {util:.0f}%"
            if util is not None
            else "Утилизация канала в пике за период инцидента: данные недоступны"
        )
    lines.append("Просим взять в работу.")

    subject = f"Проблема на канале связи {service}: {address}"
    body = "\r\n".join(lines)
    return subject, body


# ─────────────────────────────────────────────────────────────────────────────
# ШАБЛОН ПИСЬМА ДЛЯ SITE-АЛЕРТОВ («Потери до <имя площадки>»).
# Пока текст идентичен канальным алертам — правьте строки ниже под свои нужды,
# на канальные письма (build_provider_email выше) это не повлияет.
# ─────────────────────────────────────────────────────────────────────────────

def build_site_provider_email(report: IncidentReport) -> tuple[str, str]:
    """(subject, body) письма оператору для site-алерта. Обычный текст, CRLF."""
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    contract = _contract(report, cod)
    address  = _address(report)
    service  = _service(report)

    channel_down = report.decision == IncidentDecision.CHANNEL_DOWN
    if channel_down:
        loss_line = "        - Потери ICMP: 100% (канал недоступен)"
    else:
        loss_line = f"        - Потери ICMP: {_report_loss_pct(report):.0f}%"

    lines = [
        f"Здравствуйте! Наблюдаются проблема по адресу: {address}. Услуга {service}.",
        f"Договор: {contract}",
        f"Результаты проверки L2VPN-транспорта:",
        loss_line,
    ]
    if not channel_down:
        util = report.utilization_pct
        lines.append(
            f"Утилизация канала в пике за период инцидента: {util:.0f}%"
            if util is not None
            else "Утилизация канала в пике за период инцидента: данные недоступны"
        )
    lines.append("Просим взять в работу.")

    subject = f"Проблема на канале связи {service}: {address}"
    body = "\r\n".join(lines)
    return subject, body


# ─────────────────────────────────────────────────────────────────────────────
# ПИСЬМО ПРОВАЙДЕРУ РЕЗЕРВНОГО КАНАЛА (эскалация RESERVE_UNAVAILABLE):
# основной канал в порядке проверки/переключения не участвует — это письмо
# ИМЕННО про то, что резервный канал (найден недоступным при попытке
# переключения) сам простаивает. report.pyrus_channel здесь — резервный
# канал (см. pipeline._attempt_channel_switch).
# ─────────────────────────────────────────────────────────────────────────────

def build_reserve_unavailable_email(report: IncidentReport) -> tuple[str, str]:
    """(subject, body) письма провайдеру резервного канала. Обычный текст, CRLF."""
    address = _address(report)
    service = _service(report)
    ch      = report.pyrus_channel   # резервный канал
    contract = ch.contract if ch and ch.contract else "—"

    lines = [
        f"Здравствуйте! Наблюдается недоступность канала связи (резервного) по адресу: {address}. "
        f"Услуга {service}.",
        f"Договор: {contract}",
        "Канал недоступен (потери ICMP 100%).",
        "Просим взять в работу.",
    ]
    subject = f"Проблема на канале связи {service}: {address}"
    body = "\r\n".join(lines)
    return subject, body


def channel_email(report: IncidentReport) -> str | None:
    """
    Email провайдера из сматченного канала Pyrus (ChannelInfo.email, cell 52
    — свободный текст, в нём кроме email нередко указан ещё и телефон,
    извлекаем только email).

    Пока нигде не подключён автоматически — используется, только если
    явно передан вызывающим кодом как `to_override` в resolve_recipient/
    send_provider_notification (см. их docstring).
    """
    ch = report.pyrus_channel
    return extract_email(ch.email) if ch else None


def resolve_recipient(
    report: IncidentReport,
    settings,
    to_override: str | None = None,
) -> str | None:
    """
    Email оператора: `to_override` (если передан явно вызывающим кодом —
    например, channel_email(report)) → PROVIDER_EMAILS[провайдер] →
    запасной адрес Settings.mail_to_default.
    """
    if to_override:
        return to_override
    cod = get_cod_by_name(report.problem.cod_name)
    operator = _operator(report, cod)
    return get_provider_email(operator) or (settings.mail_to_default or None)


class MailClient:
    """HTTP-клиент к mail-service (POST /emails/{mailbox}/send)."""

    def __init__(self, settings) -> None:
        self._base_url = settings.mail_service_url.rstrip("/")
        self._mailbox  = settings.mailbox
        self._session  = requests.Session()
        self._session.verify = settings.mail_verify_ssl
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })

    def send(self, to_addr: str, subject: str, body: str, cc_addrs: list[str] | None = None) -> str:
        url = f"{self._base_url}/emails/{self._mailbox}/send"
        payload = {
            "to_recipients": [to_addr],
            "subject":       subject,
            "body":          body,
        }
        if cc_addrs:
            payload["cc_recipients"] = cc_addrs
        resp = self._session.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        try:
            return resp.json().get("message_id", "")
        except ValueError:
            return ""


# Решения, по которым уместно обращение к оператору. HIGH_UTILIZATION сюда
# не входит: канал перегружен собственным трафиком, вины оператора нет.
_MAILABLE_DECISIONS = frozenset({
    IncidentDecision.CHANNEL_DOWN,
    IncidentDecision.DEGRADED_CHANNEL,
    IncidentDecision.RESERVE_UNAVAILABLE,
})


def send_provider_notification(
    settings,
    report: IncidentReport,
    to_override: str | None = None,
) -> bool:
    """
    Формирует и шлёт письмо оператору через mail-service. Возвращает True
    при успешной отправке. Блокирующая (HTTP) — из asyncio вызывать через
    to_thread.

    `to_override` — необязательный явный адрес получателя (например,
    channel_email(report) — email из канала Pyrus), приоритетнее
    PROVIDER_EMAILS/MAIL_TO_DEFAULT. Сейчас нигде не передаётся — сама
    возможность отправки готова, включать как источник получателя по
    умолчанию пока не нужно.

    Копия письма — Settings.mail_cc_list (MAIL_CC в .env, через запятую),
    если задана.
    """
    if not settings.mail_enabled:
        logger.info("Почта не сконфигурирована (MAIL_SERVICE_URL) — письмо оператору не отправляется (host=%s).",
                    report.problem.host_name)
        return False

    if report.decision not in _MAILABLE_DECISIONS:
        logger.info(
            "Письмо оператору не требуется для decision=%s (host=%s)",
            report.decision.value if report.decision else None,
            report.problem.host_name,
        )
        return False

    to_addr = resolve_recipient(report, settings, to_override=to_override)
    if not to_addr:
        logger.warning(
            "Email оператора не определён (нет в PROVIDER_EMAILS и не задан "
            "MAIL_TO_DEFAULT) — письмо пропущено для host=%s",
            report.problem.host_name,
        )
        return False

    if report.decision == IncidentDecision.RESERVE_UNAVAILABLE:
        subject, body = build_reserve_unavailable_email(report)
    elif report.problem.site_alert:
        subject, body = build_site_provider_email(report)
    else:
        subject, body = build_provider_email(report)
    try:
        message_id = MailClient(settings).send(to_addr, subject, body, cc_addrs=settings.mail_cc_list)
        logger.info("Письмо оператору отправлено на %s (копия: %s) (host=%s, message_id=%s)",
                    to_addr, settings.mail_cc_list or "—", report.problem.host_name, message_id)
        return True
    except Exception as exc:
        logger.error("Ошибка отправки письма оператору %s: %s", to_addr, exc)
        return False
