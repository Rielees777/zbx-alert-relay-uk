"""
mailer.py — отправка обращений оператору связи напрямую по email (SMTP).

Дополняет уведомление в чат (notifier.py): по тому же инциденту формирует
письмо оператору по шаблону обращения и шлёт его на email провайдера.

Адрес получателя: сначала PROVIDER_EMAILS[провайдер] (const.py), где провайдер
берётся из сматченного канала Pyrus; если провайдера там нет — на запасной
Settings.mail_to_default. Если ни того, ни другого — письмо не отправляется.

Инертен, пока не заданы креды почты (Settings.mail_enabled == False), — так
что подключение реального сервиса не требуется для остальной работы.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from const import get_cod_by_name, get_provider_email
from models import IncidentDecision, IncidentReport
from notifier import _avg_loss_pct, _contract, _operator

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
    """(subject, body) письма оператору по шаблону обращения."""
    p   = report.problem
    cod = get_cod_by_name(p.cod_name)

    contract = _contract(report, cod)
    address  = _address(report)
    service  = _service(report)

    if report.decision == IncidentDecision.CHANNEL_DOWN:
        loss_line = "        - Потери ICMP: 100% (канал недоступен)"
    else:
        loss_line = f"        - Потери ICMP: {_avg_loss_pct(report.ping_results):.0f}%"

    util = report.utilization_pct
    util_line = (
        f"Утилизация канала в пике за период инцидента: {util:.0f}%"
        if util is not None
        else "Утилизация канала в пике за период инцидента: данные недоступны"
    )

    subject = f"Проблема на канале связи {service}: {address}"
    body = (
        f"Здравствуйте! Наблюдаются проблема по адресу: {address}. Услуга {service}.\n"
        f"Договор: {contract}\n"
        f"Результаты проверки L2VPN-транспорта:\n"
        f"{loss_line}\n"
        f"{util_line}\n"
        f"Просим взять в работу."
    )
    return subject, body


def resolve_recipient(report: IncidentReport, settings) -> str | None:
    """Email оператора: по провайдеру из канала Pyrus, иначе запасной адрес."""
    cod = get_cod_by_name(report.problem.cod_name)
    operator = _operator(report, cod)
    return get_provider_email(operator) or (settings.mail_to_default or None)


class MailClient:
    """Тонкий SMTP-клиент на stdlib smtplib/email."""

    def __init__(self, settings) -> None:
        self._s = settings

    def send(self, to_addr: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"]    = self._s.mail_from
        msg["To"]      = to_addr
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(self._s.mail_host, self._s.mail_port, timeout=30) as smtp:
            if self._s.mail_use_tls:
                smtp.starttls()
            if self._s.mail_user:
                smtp.login(self._s.mail_user, self._s.mail_password)
            smtp.send_message(msg)


def send_provider_notification(settings, report: IncidentReport) -> bool:
    """Формирует и шлёт письмо оператору. Возвращает True при успешной
    отправке. Блокирующая (SMTP) — из asyncio вызывать через to_thread."""
    if not settings.mail_enabled:
        logger.debug("Почта не сконфигурирована (MAIL_HOST/MAIL_FROM) — письмо не отправляется.")
        return False

    to_addr = resolve_recipient(report, settings)
    if not to_addr:
        logger.warning(
            "Email оператора не определён (нет в PROVIDER_EMAILS и не задан "
            "MAIL_TO_DEFAULT) — письмо пропущено для host=%s",
            report.problem.host_name,
        )
        return False

    subject, body = build_provider_email(report)
    try:
        MailClient(settings).send(to_addr, subject, body)
        logger.info("Письмо оператору отправлено на %s (host=%s)", to_addr, report.problem.host_name)
        return True
    except Exception as exc:
        logger.error("Ошибка отправки письма оператору %s: %s", to_addr, exc)
        return False
