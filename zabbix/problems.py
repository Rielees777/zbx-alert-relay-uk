from __future__ import annotations

import logging
import time

from const import COD, CODs, MIN_ALERT_AGE_SEC
from models import RpmProblem
from trigger_parser import TriggerInfo
from zabbix.client import ZabbixClient

logger = logging.getLogger(__name__)

_EVENT_OUTPUT = ["eventid", "objectid", "name", "severity", "clock", "r_eventid"]


class ZabbixProblems(ZabbixClient):

    def get_active_rpm_problems(self, pattern: str) -> list[RpmProblem]:
        """
        Все ОТКРЫТЫЕ проблемы по паттерну триггера, независимо от их возраста
        (problem.get отдаёт только нерешённые — окно по времени не нужно,
        иначе терялись бы старые незакрытые алерты). Слишком молодые
        (< MIN_ALERT_AGE_SEC) откладываются до следующего цикла.
        """
        self._ensure_connected()
        events = self._fetch_open_problem_events(pattern)
        min_age = MIN_ALERT_AGE_SEC
        now = time.time()
        active = [
            e for e in events
            if e.get("r_eventid", "0") == "0"
            and now - int(e.get("clock", 0)) >= min_age
        ]
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
        trigger_name = event.get("name") or ""
        trigger      = TriggerInfo(trigger_name)
        cod          = self._define_cod(trigger.node or "") if trigger.node else None

        result: list[RpmProblem] = []
        for h in event.get("hosts", []):
            host_name = h.get("name") or h.get("host", "")

            # Site-триггер обязан указывать то же имя площадки, что и
            # видимое имя узла в том же алерте. Несовпадение — признак
            # того, что триггер срабатывает не по своему хосту; такие
            # алерты не обрабатываем вовсе (уже прилетали некорректные
            # сообщения по чужим площадкам).
            if trigger.is_site and not trigger.matches_visible_name(host_name):
                logger.warning(
                    "Site-триггер %r (площадка %r) не совпадает с видимым "
                    "именем узла %r — алерт пропущен",
                    trigger_name, trigger.site_name, host_name,
                )
                continue

            result.append(RpmProblem(
                eventid=event["eventid"],
                host_name=host_name,
                host_tech=h.get("host", ""),
                ip=ip_by_host.get(h["hostid"], ""),
                cod_name=cod.name if cod else None,
                cod_ip=cod.ip   if cod else None,
                provider=trigger.provider,      # нормализованный ("ТТК")
                severity=int(event.get("severity", 0)),
                started=int(event.get("clock", 0)),
                resolved=resolved_clock,
                trigger_name=trigger_name,
                channel_type=trigger.channel_type,
                trigger_loss_pct=trigger.loss_pct,
                hostid=h["hostid"],
                channel_spec=trigger.channel_spec,
                site_alert=trigger.is_site,
            ))
        return result

    def get_channel_utilization_pct(
        self,
        hostid:       str,
        channel_spec: str | None,
        minutes:      int,
    ) -> float | None:
        """
        Пик утилизации канала за последние `minutes` минут:
            max(isp.speed.in, isp.speed.out за окно) / isp.bandwidth × 100

        isp.bandwidth.[channel_spec] — статичная номинальная ширина канала;
        isp.speed.in/out.[channel_spec] — фактический трафик по направлениям
        (несмотря на имя "speed", это не заявленная скорость, а измеренная).
        Проверено на реальных данных: результат совпадает с готовым
        isp.calc.in/out того же канала.

        Возвращает None, если channel_spec не определён или нужные item'ы /
        данные не найдены — пайплайн трактует это как «утилизация неизвестна».
        """
        if not channel_spec:
            return None
        self._ensure_connected()

        items = self._zapi.item.get(
            hostids=[hostid],
            output=["itemid", "key_", "value_type", "lastvalue"],
            search={"key_": f"[{channel_spec}]"},
        )
        if not items:
            return None

        traffic_items  = [it for it in items if ".speed.in." in it["key_"] or ".speed.out." in it["key_"]]
        capacity_items = [it for it in items if "bandwidth" in it["key_"]]
        if not traffic_items or not capacity_items:
            return None

        capacity_bps = self._safe_float(capacity_items[0].get("lastvalue"))
        if not capacity_bps or capacity_bps <= 0:
            return None

        time_from    = int(time.time()) - minutes * 60
        traffic_peak = 0.0
        for it in traffic_items:
            hist = self._zapi.history.get(
                itemids=[it["itemid"]],
                time_from=time_from,
                history=int(it["value_type"]),
                output="extend",
            )
            values = [self._safe_float(h.get("value")) for h in hist]
            values = [v for v in values if v is not None]
            if values:
                traffic_peak = max(traffic_peak, max(values))

        return traffic_peak / capacity_bps * 100

    @staticmethod
    def _safe_float(value) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _define_cod(node: str) -> COD | None:
        node_lower = node.lower()
        cods = CODs()
        for cod in (cods.o2, cods.ix, cods.n11, cods.m1):
            if cod.name in node_lower:
                return cod
        return None

    def _fetch_open_problem_events(self, pattern: str) -> list[dict]:
        """
        Текущие открытые проблемы (problem.get) по паттерну имени, затем их
        события (event.get по eventid) — только у event.get есть selectHosts.
        """
        problems = self._zapi.problem.get(
            output=["eventid"],
            search={"name": pattern},
            source=0,
            object=0,
        )
        eventids = [p["eventid"] for p in problems]
        if not eventids:
            return []
        return self._zapi.event.get(
            output=_EVENT_OUTPUT,
            eventids=eventids,
            selectHosts=["hostid", "host", "name"],
            source=0,
            object=0,
        )

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
