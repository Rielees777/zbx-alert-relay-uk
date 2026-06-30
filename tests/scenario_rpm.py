"""
tests/scenario_rpm.py — сквозной тестовый сценарий обработки RPM-алерта.

Что проверяет за один прогон:
  1. Zabbix  — условно «прилетает» алерт по триггеру
     "RPM потери до m1-ttk-l2vpn - 20 %" (синтетическое событие, реальный
     разбор имени триггера → провайдер, узел, COD).
  2. Junos   — реальные парсер интерфейсов и pinger прогоняются на
     синтетических данных «железа» (поддельный Device, без подключения).
  3. Pyrus   — поход на сам сервер за реестром каналов связи, сопоставление
     задачи по IP роутера и извлечение договора нужной услуги (l2vpn).

Режимы Pyrus:
  • РЕАЛЬНЫЙ  — если заданы PYRUS_LOGIN / PYRUS_TOKEN / PYRUS_FORM_ID,
    скрипт идёт на https://pyrus.sovcombank.ru за реальным реестром.
  • OFFLINE   — иначе используется встроенный синтетический реестр, чтобы
    можно было проверить всю механику без доступа к корпоративной сети.

Запуск:
    python tests/scenario_rpm.py

Необязательные переменные окружения:
    PYRUS_LOGIN, PYRUS_TOKEN, PYRUS_FORM_ID  — доступ к реальному Pyrus
    TEST_ROUTER_IP                           — IP роутера для матчинга
    TEST_HOSTNAME                            — имя хоста Zabbix
"""

from __future__ import annotations

import os
import sys
import time
import types
import xml.etree.ElementTree as ET

# Импорты модулей проекта работают из корня репозитория.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TRIGGER_NAME = "RPM потери до m1-ttk-l2vpn - 20 %"
LOSS_PCT     = 20   # синтетические потери на L2VPN-линке


# ───────────────────────── Заглушка jnpr (для offline-запуска) ──────────────
def _ensure_jnpr() -> None:
    """
    Pinger лениво импортирует jnpr.junos.exception.RpcError. Если junos-eznc
    не установлен (тестовая среда), подкладываем минимальную заглушку, чтобы
    реальный код pinger отработал на синтетике. В рабочей среде, где junos-eznc
    установлен, ничего не подменяем.
    """
    try:
        import jnpr.junos  # noqa: F401
        return
    except Exception:
        pass

    jnpr     = types.ModuleType("jnpr")
    junos    = types.ModuleType("jnpr.junos")
    exc      = types.ModuleType("jnpr.junos.exception")

    class RpcError(Exception):
        ...

    class Device:  # не используется — _connect мы подменяем
        def __init__(self, *a, **k): ...

    exc.RpcError   = RpcError
    junos.Device   = Device
    junos.exception = exc
    jnpr.junos     = junos
    sys.modules.update({
        "jnpr": jnpr,
        "jnpr.junos": junos,
        "jnpr.junos.exception": exc,
    })


# ───────────────────────── Синтетические данные «железа» Junos ──────────────
def _interface_xml(description: str, local_ip: str) -> ET.Element:
    """get-interface-information с одним L2VPN-логическим интерфейсом."""
    root = ET.Element("interface-information")
    phys = ET.SubElement(root, "physical-interface")
    ET.SubElement(phys, "name").text        = "ge-0/0/0"
    ET.SubElement(phys, "description").text  = description
    log = ET.SubElement(phys, "logical-interface")
    ET.SubElement(log, "name").text          = "ge-0/0/0.0"
    ET.SubElement(log, "description").text    = description
    af = ET.SubElement(log, "address-family")
    ET.SubElement(af, "address-family-name").text = "inet"
    ia = ET.SubElement(af, "interface-address")
    ET.SubElement(ia, "ifa-local").text      = local_ip
    return root


def _ping_xml(sent: int, received: int) -> ET.Element:
    """Ответ rpc.ping с заданным числом отправленных/полученных пакетов."""
    root = ET.Element("ping-results")
    summ = ET.SubElement(root, "probe-results-summary")
    ET.SubElement(summ, "probes-sent").text        = str(sent)
    ET.SubElement(summ, "responses-received").text = str(received)
    return root


class _FakeRpc:
    def __init__(self, iface_xml: ET.Element, ping_xml: ET.Element) -> None:
        self._iface = iface_xml
        self._ping  = ping_xml

    def get_interface_information(self, detail: bool = True):
        return self._iface

    def ping(self, **kwargs):
        return self._ping


class _FakeDevice:
    """Имитация jnpr Device: контекст-менеджер с .rpc."""

    def __init__(self, iface_xml: ET.Element, ping_xml: ET.Element) -> None:
        self.rpc = _FakeRpc(iface_xml, ping_xml)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ───────────────────────── Синтетический Zabbix ────────────────────────────
class _FakeZabbixApi:
    """Отдаёт заранее подготовленную RPM-проблему вместо реального Zabbix."""

    def __init__(self, problems) -> None:
        self._problems = problems

    def get_active_rpm_problems(self, pattern: str, minutes: int = 5):
        return list(self._problems)


def _synthetic_problem(trigger_name: str, router_ip: str, hostname: str):
    """
    Собирает RpmProblem тем же кодом, что и в проде (_build_rpm_problem):
    реальный разбор триггера → провайдер/узел/COD, IP берём из «hostinterface».
    """
    from models import ZabbixConfig
    from zabbix.problems import ZabbixProblems

    zp = ZabbixProblems(ZabbixConfig(url="http://offline.local"))  # без подключения
    event = {
        "eventid":   "9000001",
        "name":      trigger_name,
        "severity":  "4",
        "clock":     str(int(time.time()) - 600),
        "r_eventid": "0",
        "hosts":     [{"hostid": "1", "name": hostname, "host": hostname}],
    }
    problems = zp._build_rpm_problem(event, {"1": router_ip}, resolved_clock=0)
    return problems[0]


def _synthetic_junos(problem):
    """JunosApi с подменённым _connect → синтетические интерфейс и ping."""
    from junos import JunosApi

    junos = JunosApi(types.SimpleNamespace())   # settings не нужен — _connect подменён

    local_ip    = problem.cod_ip or "10.70.138.50"
    description  = f"{problem.cod_name}-ttk-l2vpn uplink"   # содержит COD и 'l2vpn'
    iface_xml   = _interface_xml(description, local_ip)
    ping_xml    = _ping_xml(sent=100, received=100 - LOSS_PCT)

    junos._connect = lambda host: _FakeDevice(iface_xml, ping_xml)
    return junos


# ───────────────────────── Реестр Pyrus ────────────────────────────────────
def _pyrus_matcher_real():
    from matcher import RegistryMatcher
    from pyrus import PyrusClient, PyrusSiteParser

    login = os.environ["PYRUS_LOGIN"]
    key   = os.environ["PYRUS_TOKEN"]
    form  = int(os.environ["PYRUS_FORM_ID"])

    client = PyrusClient()
    tasks  = client.get_registry(form, login, key)
    sites  = PyrusSiteParser.parse_many(tasks)
    return RegistryMatcher(sites), sites


def _pyrus_matcher_offline():
    """Встроенный синтетический реестр — повторяет структуру задачи Pyrus."""
    from matcher import RegistryMatcher
    from models import ChannelInfo, PyrusSite

    sites = [
        PyrusSite(
            task_id=7,
            directorate="УК-Саратов",
            zabbix_hostname="uk-srt-rabochaya145a-r",
            router_ip="10.20.30.40",
            address="г. Саратов, Рабочая ул дом №145а",
            city="Саратов",
            channels=[
                ChannelInfo(provider="ТТК", channel_id="TTK-L2VPN-1", bandwidth=100000,
                            contract="ДГ-2024/00567", ip_address="10.20.30.40", technology="L2VPN"),
                ChannelInfo(provider="ТТК", channel_id="TTK-NET-1", bandwidth=50000,
                            contract="ДГ-2024/00999", ip_address="10.20.30.41", technology="Интернет"),
            ],
        ),
        PyrusSite(
            task_id=8,
            directorate="УК-Москва",
            zabbix_hostname="uk-msk-host-r",
            router_ip="10.50.60.70",
            address="г. Москва, Тверская 1",
            city="Москва",
            channels=[
                ChannelInfo(provider="Ростелеком", channel_id="RT-L2VPN-1", bandwidth=200000,
                            contract="ДГ-2024/01000", ip_address="10.50.60.70", technology="L2VPN"),
            ],
        ),
    ]
    return RegistryMatcher(sites), sites


def _pick_target(sites):
    """Берём задачу с IP роутера и подходящим каналом (ТТК + l2vpn)."""
    from trigger_parser import find_channel_by_trigger

    for s in sites:
        if s.ip_key and find_channel_by_trigger(TRIGGER_NAME, s):
            return s
    for s in sites:                       # запасной вариант — любая с IP
        if s.ip_key:
            return s
    return None


# ───────────────────────── Прогон сценария ─────────────────────────────────
def main() -> int:
    _ensure_jnpr()

    from pipeline import run as run_pipeline
    from notifier import build_notification
    from report import print_incident_reports

    real = all(os.environ.get(k) for k in ("PYRUS_LOGIN", "PYRUS_TOKEN", "PYRUS_FORM_ID"))

    print("=" * 70)
    print("СЦЕНАРИЙ: обработка RPM-алерта")
    print(f"Триггер Zabbix: {TRIGGER_NAME!r}")
    print("=" * 70)

    if real:
        from pyrus import PyrusClient
        print(f"\n[Pyrus] режим РЕАЛЬНЫЙ — иду на {PyrusClient.BASE_URL}")
        matcher, sites = _pyrus_matcher_real()
    else:
        print("\n[Pyrus] режим OFFLINE — синтетический реестр")
        print("        (задайте PYRUS_LOGIN/PYRUS_TOKEN/PYRUS_FORM_ID для реального сервера)")
        matcher, sites = _pyrus_matcher_offline()

    with_ip = sum(1 for s in sites if s.ip_key)
    uk      = sum(1 for s in sites if s.is_uk)
    print(f"[Pyrus] задач: {len(sites)} | c IP роутера: {with_ip} | УК-*: {uk}")

    # Цель сценария (IP роутера = ключ матчинга по IP)
    ip   = os.environ.get("TEST_ROUTER_IP")
    host = os.environ.get("TEST_HOSTNAME")
    if not ip:
        target = _pick_target(sites)
        if target is None:
            print("\n[ОШИБКА] В реестре нет задачи с IP роутера и каналом ТТК/l2vpn.")
            print("         Задайте TEST_ROUTER_IP вручную.")
            return 1
        ip   = target.router_ip
        host = target.zabbix_hostname or "test-host-r"
    host = host or "test-host-r"
    print(f"[Цель ]  host={host}  router_ip={ip}")

    # 1. Синтетический алерт Zabbix → RpmProblem
    problem = _synthetic_problem(TRIGGER_NAME, ip, host)
    print(f"\n[Zabbix] RpmProblem: host={problem.host_name} ip={problem.ip} "
          f"cod={problem.cod_name} provider={problem.provider}")

    # 2. Junos на синтетических данных + 3. реальный Pyrus-matcher
    junos = _synthetic_junos(problem)
    zapi  = _FakeZabbixApi([problem])
    reports = run_pipeline(zapi, junos, matcher)

    print_incident_reports(reports)

    # Итог: матч Pyrus, договор и готовое сообщение
    for r in reports:
        site = r.pyrus_site
        ch   = r.pyrus_channel
        print("─" * 70)
        if site:
            print(f"[Pyrus]  matched task:{site.task_id}  ({site.directorate})")
            if ch:
                print(f"[Pyrus]  канал: провайдер={ch.provider} услуга={ch.technology} "
                      f"договор={ch.contract}")
            else:
                print("[Pyrus]  канал не определён (нет ТТК/l2vpn) — договор будет «—»")
        else:
            print(f"[Pyrus]  совпадения по IP {problem.ip} не найдено — договор будет «—»")

        msg = build_notification(r)
        print("\n--- СООБЩЕНИЕ ОПЕРАТОРУ ---")
        print(msg if msg else "(для этого решения сообщение не формируется)")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
