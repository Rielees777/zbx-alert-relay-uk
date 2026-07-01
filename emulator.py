"""
emulator.py — построение эмулированных Zabbix/Junos API и Pyrus-matcher
из одного JSON-файла с алертами.

Используется:
  • scheduler.py       — временная замена реальных Zabbix/Junos (константа
    EMULATOR_FIXTURE), чтобы гонять боевой пайплайн и слать реальные
    сообщения ботом в реальный чат по данным из файла, без живого
    Zabbix/оборудования.
  • tests/alert_emulator.py — разовый прогон файла с выводом в консоль,
    без бота (для быстрой проверки без правки scheduler.py).

Эмулируются ТОЛЬКО источники данных (Zabbix API, Junos API). Разбор
триггера, пороги, ветвление decision, матчинг Pyrus и текст сообщения —
настоящий код проекта (trigger_parser, pipeline, matcher, notifier).

Схема JSON-файла:
{
  "pyrus_sites": [                     // необязательно; если задано —
                                        // используется ВМЕСТО реального
                                        // реестра Pyrus (offline-режим).
                                        // Если ключа нет — при вызове из
                                        // scheduler.py используется реальный
                                        // Pyrus (загруженный при старте).
    { ...поля модели PyrusSite:
      task_id, directorate, zabbix_hostname, router_ip, address, city,
      channels: [ {provider, service, technology, contract, bandwidth,
                    channel_id, ip_address}, ... ]   // "дополнительные
                                                      // сервисы" канала —
                                                      // просто ещё элементы
                                                      // этого списка
    }, ...
  ],

  "alerts": [                          // список алертов; каждый — как один
                                        // Zabbix-инцидент. Можно держать
                                        // несколько одновременно активных.
    {
      "notes": "свободный текст, только для документации",

      "zabbix_event": {                // событие Zabbix as-is из event.get
        "eventid": "900001",           // ключ дедупликации отправки — чтобы
                                        // получить НОВОЕ сообщение при
                                        // повторном тесте, смените eventid
        "name": "RPM потери до m1-rtk-l2vpn - 20 %",
        "severity": "3",
        "clock": 1719800000,
        "r_eventid": "0",
        "hosts": [{"hostid": "11877", "host": "10.70.138.98", "name": "..."}]
      },
      "host_ip": "10.70.138.98",       // management-IP; либо "ip_by_host":
                                        // {"11877": "10.70.138.98"} для
                                        // нескольких хостов в событии

      "junos": {                       // данные "с сетевого оборудования"
        "l2vpn_links": [               // список PingResult:
          {"interface": "ge-0/0/0.0", "description": "...",
           "local_ip": "10.70.138.50", "remote_ip": "10.70.138.49",
           "loss": 20}
        ],
        "ipsec_links": [],
        "unreachable": false,          // true → устройство недоступно по
                                        // SSH (ConnectError) → CHANNEL_DOWN
        "error": null                  // прочая ошибка обработки
      },

      "utilization": {                 // проверяется только если потери
                                        // не 100%; можно не указывать (None)
        "pct": 35.0                    // готовый % ...
        // ... либо сырые данные — тогда считает РЕАЛЬНЫЙ метод
        // ZabbixProblems.get_channel_utilization_pct:
        // "bandwidth_bps": 200000000,
        // "speed_in_bps": [6296, 6917, 7600, 6608],
        // "speed_out_bps": [5056, 5650, 6312, 5336]
      }
    }
  ]
}
"""

from __future__ import annotations

import json
import types
from typing import Any


def load_fixture(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _build_problem(zp, alert: dict):
    """RpmProblem реальным кодом ZabbixProblems._build_rpm_problem — та же
    трансформация Zabbix-событие → RpmProblem, что и в проде."""
    event = alert["zabbix_event"]
    if "ip_by_host" in alert:
        ip_by_host = alert["ip_by_host"]
    else:
        host_ip = alert.get("host_ip", "")
        ip_by_host = {h["hostid"]: host_ip for h in event.get("hosts", [])}

    problems = zp._build_rpm_problem(event, ip_by_host, resolved_clock=0)
    if not problems:
        raise ValueError(f"alert без хостов в zabbix_event: {alert.get('notes', '')}")
    return problems[0]


def _fake_util_zapi(channel_spec: str, bandwidth_bps: float,
                     speed_in: list, speed_out: list):
    """Фейковый _zapi, отдающий item'ы isp.* в реальном формате — чтобы
    utilization считал НАСТОЯЩИЙ метод get_channel_utilization_pct."""
    items = [
        {"itemid": "1", "key_": f"isp.bandwidth.[{channel_spec}]",
         "value_type": "3", "lastvalue": str(bandwidth_bps)},
        {"itemid": "2", "key_": f"isp.speed.in.[{channel_spec}]",
         "value_type": "3", "lastvalue": str(speed_in[-1] if speed_in else 0)},
        {"itemid": "3", "key_": f"isp.speed.out.[{channel_spec}]",
         "value_type": "3", "lastvalue": str(speed_out[-1] if speed_out else 0)},
    ]
    history_by_id = {"2": speed_in, "3": speed_out}

    class _Item:
        @staticmethod
        def get(**kwargs):
            return items

    class _History:
        @staticmethod
        def get(**kwargs):
            itemid = kwargs["itemids"][0]
            return [{"value": str(v)} for v in history_by_id.get(itemid, [])]

    return types.SimpleNamespace(item=_Item, history=_History)


class FixtureZabbixApi:
    """Эмулирует источники данных Zabbix: отдаёт заранее построенные
    RpmProblem и считает утилизацию по данным из файла."""

    def __init__(self, problems: list, util_by_key: dict[tuple, dict], real_zp) -> None:
        self._problems    = problems
        self._util_by_key = util_by_key
        self._real_zp     = real_zp

    def get_active_rpm_problems(self, pattern: str, minutes: int = 5):
        return list(self._problems)

    def get_channel_utilization_pct(self, hostid: str, channel_spec, minutes: int):
        cfg = self._util_by_key.get((hostid, channel_spec))
        if not cfg:
            return None
        if "pct" in cfg:
            return cfg["pct"]
        self._real_zp._zapi = _fake_util_zapi(
            channel_spec,
            cfg["bandwidth_bps"],
            cfg.get("speed_in_bps", []),
            cfg.get("speed_out_bps", []),
        )
        return self._real_zp.get_channel_utilization_pct(hostid, channel_spec, minutes)


class FixtureJunosApi:
    """Эмулирует данные, которые дало бы сетевое оборудование, по каждому
    алерту отдельно (ключ — eventid его zabbix_event)."""

    def __init__(self, junos_by_eventid: dict[str, dict]) -> None:
        self._by_eventid = junos_by_eventid

    def analyze_problem(self, problem, count: int = 100):
        from models import IncidentReport, PingResult

        cfg = self._by_eventid.get(problem.eventid, {})
        if cfg.get("unreachable"):
            return IncidentReport(
                problem=problem,
                error=cfg.get("error") or f"Устройство {problem.ip} недоступно (эмулятор)",
                unreachable=True,
            )
        if cfg.get("error"):
            return IncidentReport(problem=problem, error=cfg["error"])

        links = [PingResult(**link) for link in cfg.get("l2vpn_links", [])]
        return IncidentReport(problem=problem, ping_results=links)

    def analyze_ipsec(self, problem, count: int = 100):
        from models import PingResult
        cfg = self._by_eventid.get(problem.eventid, {})
        return [PingResult(**link) for link in cfg.get("ipsec_links", [])]


def build_matcher(fixture: dict):
    """None означает «фикстура не задаёт свой реестр Pyrus» — вызывающий
    код должен в этом случае использовать реальный (если он есть)."""
    sites_cfg = fixture.get("pyrus_sites")
    if not sites_cfg:
        return None
    from matcher import RegistryMatcher
    from models import PyrusSite
    return RegistryMatcher([PyrusSite(**s) for s in sites_cfg])


def load_emulated_apis(path: str) -> tuple[Any, Any, Any]:
    """
    Строит (zabbix_api, junos_api, matcher_or_None) из JSON-файла целиком.
    Файл перечитывается при каждом вызове — можно править его прямо во
    время работы scheduler.py, без перезапуска процесса.
    """
    from models import ZabbixConfig
    from zabbix.problems import ZabbixProblems

    fixture = load_fixture(path)
    alerts  = fixture.get("alerts", [])

    zp = ZabbixProblems(ZabbixConfig(url="http://emulated"))

    problems: list = []
    util_by_key:     dict[tuple, dict] = {}
    junos_by_eventid: dict[str, dict]  = {}

    for alert in alerts:
        problem = _build_problem(zp, alert)
        problems.append(problem)
        if "utilization" in alert:
            util_by_key[(problem.hostid, problem.channel_spec)] = alert["utilization"]
        junos_by_eventid[problem.eventid] = alert.get("junos", {})

    zabbix_api = FixtureZabbixApi(problems, util_by_key, zp)
    junos_api  = FixtureJunosApi(junos_by_eventid)
    matcher    = build_matcher(fixture)
    return zabbix_api, junos_api, matcher
