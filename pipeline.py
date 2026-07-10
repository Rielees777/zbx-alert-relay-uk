from __future__ import annotations

import ipaddress
import logging

from const import (
    ALLOWED_CHANNEL_TYPES,
    ALLOWED_IP_NETWORK,
    CHANNEL_UTIL_THRESHOLD_PCT,
    L2VPN_LOSS_THRESHOLD_PCT,
    PING_COUNT,
    TRIGGER_PATTERNS,
    UTIL_LOOKBACK_MINUTES,
    cod_ips,
)
from models import IncidentDecision, IncidentReport, RpmProblem

logger = logging.getLogger(__name__)


def run(zabbix_api, junos_api, matcher=None, skip_eventids: frozenset[str] = frozenset()) -> list[IncidentReport]:
    problems = _collect_problems(zabbix_api, skip_eventids)
    if not problems:
        logger.debug("Активных RPM-проблем для обработки не найдено.")
        return []

    logger.info("Найдено RPM-проблем: %d", len(problems))
    reports: list[IncidentReport] = []
    for problem in problems:
        report = _process_problem(zabbix_api, junos_api, problem)
        _attach_pyrus(report, matcher)
        reports.append(report)
        _log_report(report)
    return reports


def _in_allowed_network(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in ALLOWED_IP_NETWORK
    except ValueError:
        return False


def _collect_problems(
    zabbix_api,
    skip_eventids: frozenset[str] = frozenset(),
) -> list[RpmProblem]:
    seen:   set[str]         = set()
    result: list[RpmProblem] = []
    cod_ip_set = cod_ips()
    for pattern in TRIGGER_PATTERNS:
        for p in zabbix_api.get_active_rpm_problems(pattern=pattern):
            # Обрабатываем только узлы из ALLOWED_IP_NETWORK — остальные
            # отсекаются здесь, до Junos-проверок и поиска в реестре.
            if not _in_allowed_network(p.ip):
                logger.debug("IP %r вне сети %s — пропуск: %s",
                             p.ip, ALLOWED_IP_NETWORK, p.trigger_name)
                continue
            # ЦОД — хабовая сторона каналов, не площадка; целью отработки
            # алертов не является, даже если его IP попадает в сеть выше
            # (m1/n11 — попадают).
            if p.ip in cod_ip_set:
                logger.debug("IP %r принадлежит ЦОД (%s) — пропуск: %s",
                             p.ip, p.cod_name, p.trigger_name)
                continue
            # Site-алерты ("Потери до <площадка>") обрабатываются всегда;
            # канальные — только l2vpn.
            if not p.site_alert and p.channel_type not in ALLOWED_CHANNEL_TYPES:
                logger.debug("Игнорирую не-l2vpn инцидент (channel_type=%r): %s",
                             p.channel_type, p.trigger_name)
                continue
            # Уже отработанный инцидент (письмо направлено) — больше не
            # реагируем: ни junos-проверок, ни сообщений.
            if p.eventid in skip_eventids:
                logger.debug("Инцидент %s уже отработан — пропуск", p.eventid)
                continue
            if p.eventid not in seen:
                seen.add(p.eventid)
                result.append(p)
    return result


def _process_problem(zabbix_api, junos_api, problem: RpmProblem) -> IncidentReport:
    logger.info("Проверяю: host=%s  ip=%s  cod=%s", problem.host_name, problem.ip, problem.cod_name)

    # Триггер уже сообщает 100% потерь — канал полностью недоступен,
    # пинговать устройство не нужно.
    if problem.trigger_loss_pct is not None and problem.trigger_loss_pct >= 100.0:
        logger.warning(
            "Триггер сообщает 100%% потерь: host=%s → CHANNEL_DOWN (без пинга)",
            problem.host_name,
        )
        return IncidentReport(problem=problem, decision=IncidentDecision.CHANNEL_DOWN)

    report = junos_api.analyze_problem(problem, count=PING_COUNT)

    if report.error:
        # Недоступность железки по управлению = полный обрыв канала.
        report.decision = (
            IncidentDecision.CHANNEL_DOWN if report.unreachable
            else IncidentDecision.ERROR
        )
        return report

    l2vpn_loss_pct = _loss_pct(report.ping_results, PING_COUNT)

    # Канал полностью недоступен, если L2VPN-линки не найдены на устройстве
    # (интерфейс лёг) ИЛИ линки найдены, но потери 100%.
    if not report.ping_results or l2vpn_loss_pct >= 100.0:
        logger.warning(
            "Канал полностью недоступен: host=%s → CHANNEL_DOWN",
            problem.host_name,
        )
        report.decision = IncidentDecision.CHANNEL_DOWN

    elif l2vpn_loss_pct > L2VPN_LOSS_THRESHOLD_PCT:
        logger.warning(
            "Потери L2VPN %.1f%% > %.1f%%: host=%s, cod=%s",
            l2vpn_loss_pct, L2VPN_LOSS_THRESHOLD_PCT, problem.host_name, problem.cod_name,
        )
        _handle_l2vpn_loss(zabbix_api, junos_api, report)

    else:
        logger.info("L2VPN без потерь (%.1f%%): host=%s — проверяю IPSEC", l2vpn_loss_pct, problem.host_name)
        _handle_l2vpn_ok(junos_api, report)

    return report


def _handle_l2vpn_loss(zabbix_api, junos_api, report: IncidentReport) -> None:
    util_pct = _check_channel_utilization(zabbix_api, report.problem)
    report.utilization_pct = util_pct

    if util_pct is not None and util_pct > CHANNEL_UTIL_THRESHOLD_PCT:
        logger.warning(
            "Утилизация канала %.1f%% > %.1f%%: host=%s → HIGH_UTILIZATION",
            util_pct, CHANNEL_UTIL_THRESHOLD_PCT, report.problem.host_name,
        )
        report.decision = IncidentDecision.HIGH_UTILIZATION
    else:
        logger.warning(
            "Утилизация канала %s: host=%s → DEGRADED_CHANNEL",
            f"{util_pct:.1f}%" if util_pct is not None else "неизвестна",
            report.problem.host_name,
        )
        report.decision = IncidentDecision.DEGRADED_CHANNEL
        _attach_bgp_channels(junos_api, report)


def _attach_bgp_channels(junos_api, report: IncidentReport) -> None:
    """
    Переключение каналов сейчас отключено (const.CHANNEL_SWITCHING_ENABLED) —
    почта и чат-бот пока на тестовых адресатах. Вместо переключения при
    деградации канала печатаем в консоль инвентарь каналов узла (группы и
    приоритеты из BGP-конфига), чтобы накопить статистику, как часто
    переключение реально бы потребовалось.
    """
    problem = report.problem
    if not problem.ip:
        return
    try:
        report.bgp_channels = junos_api.list_bgp_channels(problem.ip)
    except Exception as exc:
        logger.warning("Не удалось получить список каналов %s: %s", problem.ip, exc)


def _handle_l2vpn_ok(junos_api, report: IncidentReport) -> None:
    """
    L2VPN-транспорт без потерь — раз RPM всё же сработал, дело либо в
    IPSEC-тоннеле поверх канала, либо это ложное срабатывание.

    Потери по IPSEC оператору/в чат не сообщаются вовсе (это не проблема
    провайдера канала) — по замыслу единственное следствие IPSEC_LOSS:
    переключение канала на резервный (JunosApi.switch_channel), сейчас
    отключено (const.CHANNEL_SWITCHING_ENABLED). Если потерь нет нигде —
    инцидент закрывается как FALSE_POSITIVE, дальнейших действий не требует.
    """
    ipsec_results = junos_api.analyze_ipsec(report.problem, count=PING_COUNT)
    report.ipsec_results = ipsec_results

    if any(r.has_loss for r in ipsec_results):
        logger.warning("Потери в IPSEC-тоннеле: host=%s → IPSEC_LOSS", report.problem.host_name)
        report.decision = IncidentDecision.IPSEC_LOSS
    else:
        logger.info("L2VPN и IPSEC без потерь: host=%s → FALSE_POSITIVE", report.problem.host_name)
        report.decision = IncidentDecision.FALSE_POSITIVE


def _attach_pyrus(report: IncidentReport, matcher) -> None:
    if not matcher:
        logger.debug("Pyrus: matcher не задан — договор в сообщении будет «—»")
        return
    logger.debug("Pyrus: ищу задачу по ip=%r (host=%s)", report.problem.ip, report.problem.host_name)
    site = matcher.find(report.problem.ip)
    if site:
        report.pyrus_site    = site
        report.pyrus_channel = matcher.find_channel(
            site, report.problem.trigger_name, report.problem.host_name,
        )
        if report.pyrus_channel:
            logger.debug("Pyrus matched: host=%s → task:%d channel:%s contract:%s",
                         report.problem.host_name, site.task_id,
                         report.pyrus_channel.provider, report.pyrus_channel.contract)
        else:
            logger.warning(
                "Pyrus: задача task:%d найдена по ip=%r (host=%s), но канал не сопоставлен "
                "с триггером %r — договор в сообщении будет «—»",
                site.task_id, report.problem.ip, report.problem.host_name, report.problem.trigger_name,
            )
    else:
        logger.warning("Pyrus: нет совпадения для хоста %s (ip=%r) — договор в сообщении будет «—»",
                        report.problem.host_name, report.problem.ip)

def _check_channel_utilization(zabbix_api, problem: RpmProblem) -> float | None:
    return zabbix_api.get_channel_utilization_pct(
        problem.hostid, problem.channel_spec, UTIL_LOOKBACK_MINUTES,
    )


def _loss_pct(ping_results, total_count: int) -> float:
    if not ping_results or total_count <= 0:
        return 0.0
    total_loss = sum(r.loss or 0 for r in ping_results)
    total_sent = total_count * len(ping_results)
    return total_loss / total_sent * 100


def _log_report(report: IncidentReport) -> None:
    d = report.decision
    p = report.problem
    if d == IncidentDecision.ERROR:
        logger.error("ERROR %s: %s", p.host_name, report.error)
    elif d == IncidentDecision.CHANNEL_DOWN:
        logger.warning("CHANNEL_DOWN %s / %s — 100%% потерь L2VPN", p.host_name, p.cod_name)
    elif d == IncidentDecision.HIGH_UTILIZATION:
        logger.warning("HIGH_UTILIZATION %s / %s (util=%.1f%%)", p.host_name, p.cod_name, report.utilization_pct or 0)
    elif d == IncidentDecision.DEGRADED_CHANNEL:
        logger.warning("DEGRADED_CHANNEL %s / %s", p.host_name, p.cod_name)
    elif d == IncidentDecision.IPSEC_LOSS:
        logger.warning("IPSEC_LOSS %s / %s", p.host_name, p.cod_name)
    elif d == IncidentDecision.FALSE_POSITIVE:
        logger.info("FALSE_POSITIVE %s / %s — закрыть инцидент", p.host_name, p.cod_name)
