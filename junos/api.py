from __future__ import annotations

import logging

from const import JUNOS_WANT_IPSEC, JUNOS_WANT_L2VPN
from models import IncidentReport, PingResult, RpmProblem
from junos.parser import JunosInterfaceParser
from junos.pinger import JunosPinger

logger = logging.getLogger(__name__)


class JunosApi:
    def __init__(self, settings) -> None:
        self._settings = settings

    def analyze_problem(self, problem: RpmProblem, count: int = 100) -> IncidentReport:
        if not problem.ip:
            return IncidentReport(
                problem=problem,
                error=f"Нет IP для хоста '{problem.host_name}'",
            )
        if not problem.cod_name:
            return IncidentReport(
                problem=problem,
                error=f"Не удалось определить COD из триггера (host={problem.host_name})",
            )
        try:
            with self._connect(problem.ip) as dev:
                parser  = JunosInterfaceParser.from_device(dev)
                links   = parser.l2vpn_links(cod_name=problem.cod_name, want=JUNOS_WANT_L2VPN)
                pinger  = JunosPinger(dev)
                results = [pinger.ping_link(link, count=count) for link in links]
        except Exception as exc:
            return IncidentReport(
                problem=problem,
                error=f"Ошибка подключения к {problem.ip}: {exc}",
            )
        return IncidentReport(problem=problem, ping_results=results)

    def analyze_ipsec(self, problem: RpmProblem, count: int = 100) -> list[PingResult]:
        if not problem.ip or not problem.cod_name:
            return []
        try:
            with self._connect(problem.ip) as dev:
                parser = JunosInterfaceParser.from_device(dev)
                links  = parser.l2vpn_links(cod_name=problem.cod_name, want=JUNOS_WANT_IPSEC)
                pinger = JunosPinger(dev)
                return [pinger.ping_link(link, count=count) for link in links]
        except Exception as exc:
            logger.warning(
                "Ошибка ping IPSEC %s (host=%s): %s",
                problem.ip, problem.host_name, exc,
            )
            return []

    def _connect(self, host: str):
        from jnpr.junos import Device
        return Device(**self._settings.junos_kwargs(host))
