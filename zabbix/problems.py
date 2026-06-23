from __future__ import annotations

import time

from const import COD, CODs
from models import RpmProblem
from zabbix.client import ZabbixClient

_EVENT_OUTPUT = ["eventid", "objectid", "name", "severity", "clock", "r_eventid"]
_EVENT_KWARGS = dict(source=0, object=0, value=1, sortfield=["clock"], sortorder="DESC")


class ZabbixProblems(ZabbixClient):

    def get_active_rpm_problems(
        self,
        pattern: str,
        minutes: int = 5,
    ) -> list[RpmProblem]:
        self._ensure_connected()
        events = self._fetch_events(pattern, minutes)
        active = [e for e in events if e.get("r_eventid", "0") == "0"]
        if not active:
            return []

        host_ids   = sorted({h["hostid"] for e in active for h in e.get("hosts", [])})
        ip_by_host = self._ip_by_host(host_ids)

        problems: list[RpmProblem] = []
        for event in active:
            problems.extend(self._build_rpm_problem(event, ip_by_host, resolved_clock=0))
        return problems

    def _build_rpm_problem(
        self,
        event:          dict,
        ip_by_host:     dict[str, str],
        resolved_clock: int,
    ) -> list[RpmProblem]:
        parts = (event.get("name") or "").split()
        node  = parts[3] if len(parts) > 3 else ""
        cod   = self._define_cod(node) if node else None

        result: list[RpmProblem] = []
        for h in event.get("hosts", []):
            result.append(RpmProblem(
                eventid=event["eventid"],
                host_name=h.get("name") or h.get("host", ""),
                host_tech=h.get("host", ""),
                ip=ip_by_host.get(h["hostid"], ""),
                cod_name=cod.name if cod else None,
                cod_ip=cod.ip   if cod else None,
                severity=int(event.get("severity", 0)),
                started=int(event.get("clock", 0)),
                resolved=resolved_clock,
            ))
        return result

    @staticmethod
    def _define_cod(node: str) -> COD | None:
        node_lower = node.lower()
        cods = CODs()
        for cod in (cods.o2, cods.ix, cods.n11, cods.m1):
            if cod.name in node_lower:
                return cod
        return None

    def _fetch_events(self, pattern: str, minutes: int) -> list[dict]:
        params: dict = {
            **_EVENT_KWARGS,
            "output":      _EVENT_OUTPUT,
            "search":      {"name": pattern},
            "selectHosts": ["hostid", "host", "name"],
        }
        if minutes > 0:
            params["time_from"] = int(time.time()) - minutes * 60
        return self._zapi.event.get(**params)

    def _ip_by_host(self, host_ids: list[str]) -> dict[str, str]:
        if not host_ids:
            return {}
        interfaces = self._zapi.hostinterface.get(
            output=["hostid", "ip", "dns", "main"],
            hostids=host_ids,
        )
        ip_by_host: dict[str, str] = {}
        for iface in interfaces:
            hid = iface["hostid"]
            if hid not in ip_by_host or iface.get("main") == "1":
                ip_by_host[hid] = iface.get("ip") or iface.get("dns") or ""
        return ip_by_host


# ZabbixProblems is the full API for this project
ZabbixApi = ZabbixProblems
