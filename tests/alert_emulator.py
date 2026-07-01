"""
tests/alert_emulator.py — эмулятор алерта Zabbix по JSON-фикстуре.

Отдельный от zabbix_util_probe.py (читает живой Zabbix) и scenario_rpm.py
(ходит в реальный Pyrus) инструмент: прогоняет весь боевой конвейер
(pipeline.run — настоящий код проекта, без изменений) на данных, которые
НЕ читаются с живого Zabbix и сетевого оборудования, а берутся из JSON-файла.

Зачем: с тестового ПК нет доступа к самому сетевому оборудованию напрямую, а
Zabbix не генерирует нужные алерты постоянно. Один раз поймав алерт и данные
(или просто задав их вручную), их можно сохранить в JSON и повторно
прогонять через реальную логику пайплайна сколько угодно раз.

Что лежит в JSON-фикстуре:
  • zabbix_event   — событие Zabbix как из event.get (eventid, name,
    severity, clock, hosts). Можно вставить реально пойманный алерт целиком.
  • host_ip        — management-IP хоста (как из hostinterface); либо
    ip_by_host — {hostid: ip} для нескольких хостов в событии.
  • junos          — то, что "получили бы" с сетевого оборудования:
      - unreachable: true       → устройство недоступно по SSH (ConnectError)
      - error: "текст"          → прочая ошибка обработки (без unreachable)
      - l2vpn_links: [...]      → список PingResult-подобных записей
                                    {interface, description, local_ip,
                                     remote_ip, loss}
      - ipsec_links: [...]      → то же самое для IPSEC-тоннеля
  • utilization    — данные утилизации канала (проверяется только когда
    потери НЕ 100%, как и в проде):
      - {"pct": 35.0}                                   — готовый процент
      - {"bandwidth_bps": ..., "speed_in_bps": [...],
         "speed_out_bps": [...]}                        — сырые данные;
        считается РЕАЛЬНЫМ методом
        ZabbixProblems.get_channel_utilization_pct (peak(in,out)/bandwidth×100)
      - отсутствует совсем                              → None (неизвестна)
  • pyrus_site     — (опционально) одна задача реестра Pyrus (поля модели
    PyrusSite/ChannelInfo) для матчинга по IP и подстановки договора.
  • notes          — свободный текст, только для документации фикстуры.

Эмулируются ТОЛЬКО источники данных (Zabbix API, Junos API). Разбор
триггера, пороги, ветвление decision, матчинг Pyrus и текст сообщения —
настоящий код проекта (trigger_parser, pipeline, matcher, notifier).

Запуск:
    python tests/alert_emulator.py                        # DEFAULT_FIXTURE
    python tests/alert_emulator.py tests/fixtures/x.json   # свой файл
"""

from __future__ import annotations

import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

DEFAULT_FIXTURE = os.path.join(_REPO_ROOT, "tests", "fixtures", "alert_partial_loss.json")


def _load_fixture(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _build_problem(fixture: dict):
    """RpmProblem реальным кодом ZabbixProblems._build_rpm_problem —
    та же трансформация Zabbix-событие → RpmProblem, что и в проде."""
    from models import ZabbixConfig
    from zabbix.problems import ZabbixProblems

    event = fixture["zabbix_event"]
    if "ip_by_host" in fixture:
        ip_by_host = fixture["ip_by_host"]
    else:
        host_ip = fixture.get("host_ip", "")
        ip_by_host = {h["hostid"]: host_ip for h in event.get("hosts", [])}

    zp = ZabbixProblems(ZabbixConfig(url="http://emulated"))
    problems = zp._build_rpm_problem(event, ip_by_host, resolved_clock=0)
    if not problems:
        raise ValueError("zabbix_event.hosts пуст — не из чего строить RpmProblem")
    return problems[0], zp


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

    import types
    return types.SimpleNamespace(item=_Item, history=_History)


class _FixtureZabbixApi:
    """Эмулирует источники данных Zabbix: возвращает готовый RpmProblem и
    считает утилизацию либо напрямую (fixture["utilization"]["pct"]), либо
    через реальный ZabbixProblems.get_channel_utilization_pct на фейковых
    item'ах, построенных из сырых bandwidth/speed данных фикстуры."""

    def __init__(self, problem, util_cfg: dict, real_zp) -> None:
        self._problem = problem
        self._util_cfg = util_cfg or {}
        self._real_zp = real_zp

    def get_active_rpm_problems(self, pattern: str, minutes: int = 5):
        return [self._problem]

    def get_channel_utilization_pct(self, hostid: str, channel_spec, minutes: int):
        if "pct" in self._util_cfg:
            return self._util_cfg["pct"]
        if not self._util_cfg:
            return None
        self._real_zp._zapi = _fake_util_zapi(
            channel_spec,
            self._util_cfg["bandwidth_bps"],
            self._util_cfg.get("speed_in_bps", []),
            self._util_cfg.get("speed_out_bps", []),
        )
        return self._real_zp.get_channel_utilization_pct(hostid, channel_spec, minutes)


class _FixtureJunosApi:
    """Эмулирует данные, которые дало бы сетевое оборудование."""

    def __init__(self, junos_cfg: dict) -> None:
        self._cfg = junos_cfg or {}

    def analyze_problem(self, problem, count: int = 100):
        from models import IncidentReport, PingResult

        if self._cfg.get("unreachable"):
            return IncidentReport(
                problem=problem,
                error=self._cfg.get("error") or f"Устройство {problem.ip} недоступно (эмулятор)",
                unreachable=True,
            )
        if self._cfg.get("error"):
            return IncidentReport(problem=problem, error=self._cfg["error"])

        links = [PingResult(**link) for link in self._cfg.get("l2vpn_links", [])]
        return IncidentReport(problem=problem, ping_results=links)

    def analyze_ipsec(self, problem, count: int = 100):
        from models import PingResult
        return [PingResult(**link) for link in self._cfg.get("ipsec_links", [])]


def _build_matcher(fixture: dict):
    site_cfg = fixture.get("pyrus_site")
    if not site_cfg:
        return None
    from matcher import RegistryMatcher
    from models import PyrusSite
    return RegistryMatcher([PyrusSite(**site_cfg)])


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FIXTURE
    if not os.path.isfile(path):
        print(f"[ОШИБКА] файл фикстуры не найден: {path}")
        return 2

    fixture = _load_fixture(path)

    import pipeline
    from notifier import build_notification
    from report import print_incident_reports

    print("=" * 70)
    print(f"ЭМУЛЯТОР АЛЕРТА — фикстура: {path}")
    if notes := fixture.get("notes"):
        print(f"Описание: {notes}")
    print("=" * 70)

    problem, real_zp = _build_problem(fixture)
    print(f"\n[zabbix_event → RpmProblem] host={problem.host_name} ip={problem.ip} "
          f"hostid={problem.hostid}")
    print(f"    trigger={problem.trigger_name!r}")
    print(f"    channel_type={problem.channel_type} channel_spec={problem.channel_spec} "
          f"trigger_loss_pct={problem.trigger_loss_pct}")
    print(f"    cod={problem.cod_name} provider={problem.provider}")

    zabbix_api = _FixtureZabbixApi(problem, fixture.get("utilization"), real_zp)
    junos_api  = _FixtureJunosApi(fixture.get("junos"))
    matcher    = _build_matcher(fixture)

    reports = pipeline.run(zabbix_api, junos_api, matcher)

    print_incident_reports(reports)

    for r in reports:
        site = r.pyrus_site
        print("─" * 70)
        if fixture.get("pyrus_site"):
            print(f"[Pyrus] matched: {'task:' + str(site.task_id) if site else 'НЕ найдено'}")
        msg = build_notification(r)
        print("--- СООБЩЕНИЕ ОПЕРАТОРУ ---")
        print(msg if msg else "(для этого decision сообщение не формируется)")
        print()

    if not reports:
        print("\n(инцидент отфильтрован ДО обработки — см. ALLOWED_CHANNEL_TYPES в const.py)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
