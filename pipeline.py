from __future__ import annotations

import logging

from const import (
    ACTIVE_MINUTES,
    CHANNEL_UTIL_THRESHOLD_PCT,
    L2VPN_LOSS_THRESHOLD_PCT,
    PING_COUNT,
    TRIGGER_PATTERNS,
)
from models import IncidentDecision, IncidentReport, RpmProblem

logger = logging.getLogger(__name__)


def run(zabbix_api, junos_api, matcher=None) -> list[IncidentReport]:
    problems = _collect_problems(zabbix_api, ACTIVE_MINUTES)
    if not problems:
        logger.debug("Активных RPM-проблем не найдено.")
        return []

    logger.info("Найдено RPM-проблем: %d", len(problems))
    reports: list[IncidentReport] = []
    for problem in problems:
        report = _process_problem(zabbix_api, junos_api, problem)
        _attach_pyrus(report, matcher)
        reports.append(report)
        _log_report(report)
    return reports


def _collect_problems(zabbix_api, active_minutes: int) -> list[RpmProblem]:
    seen:   set[str]         = set()
    result: list[RpmProblem] = []
    for pattern in TRIGGER_PATTERNS:
        for p in zabbix_api.get_active_rpm_problems(pattern=pattern, minutes=active_minutes):
            if p.eventid not in seen:
                seen.add(p.eventid)
                result.append(p)
    return result


def _process_problem(zabbix_api, junos_api, problem: RpmProblem) -> IncidentReport:
    logger.info("Проверяю: host=%s  ip=%s  cod=%s", problem.host_name, problem.ip, problem.cod_name)

    report = junos_api.analyze_problem(problem, count=PING_COUNT)

    if report.error:
        report.decision = IncidentDecision.ERROR
        return report

    l2vpn_loss_pct = _loss_pct(report.ping_results, PING_COUNT)

    if not report.ping_results and l2vpn_loss_pct >= 100.0:
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
        _handle_l2vpn_loss(zabbix_api, report)

    else:
        logger.info("L2VPN без потерь (%.1f%%): host=%s — проверяю IPSEC", l2vpn_loss_pct, problem.host_name)
        _handle_l2vpn_ok(junos_api, report)

    return report


def _handle_l2vpn_loss(zabbix_api, report: IncidentReport) -> None:
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


def _handle_l2vpn_ok(junos_api, report: IncidentReport) -> None:
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
        return
    site = matcher.find(report.problem.host_name, report.problem.ip)
    if site:
        report.pyrus_site    = site
        report.pyrus_channel = matcher.find_channel(site, report.problem.trigger_name)
        logger.debug("Pyrus matched: host=%s → task:%d channel:%s contract:%s",
                     report.problem.host_name, site.task_id,
                     report.pyrus_channel.provider if report.pyrus_channel else None,
                     report.pyrus_channel.contract if report.pyrus_channel else None)
    else:
        logger.warning("Pyrus: нет совпадения для хоста %s", report.problem.host_name)

def _check_channel_utilization(zabbix_api, problem: RpmProblem) -> float | None:
    # TODO: реализовать поиск интерфейса через Zabbix API.
    # Пока всегда None → pipeline выбирает DEGRADED_CHANNEL.
    return None


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
