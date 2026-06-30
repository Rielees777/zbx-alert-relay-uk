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
  • РЕАЛЬНЫЙ (по умолчанию) — креды берутся из Settings (config.py / .env),
    как и в проде (scheduler._build_matcher); скрипт идёт на
    https://pyrus.sovcombank.ru за реальным реестром. Если кредов нет —
    завершается с ошибкой, а не подменяет данные синтетикой.
  • OFFLINE (только по флагу SCENARIO_OFFLINE=1) — встроенный синтетический
    реестр, чтобы проверить механику без доступа к корпоративной сети.

Креды (в .env, читает Settings):
    ZABBIX_URL, ZABBIX_TOKEN            — обязательны для Settings
    PYRUS_LOGIN, PYRUS_TOKEN, PYRUS_FORM_ID

Запуск (реальный Pyrus):
    python tests/scenario_rpm.py

Запуск (синтетика, без сети):
    SCENARIO_OFFLINE=1 python tests/scenario_rpm.py

Необязательные переменные окружения:
    TEST_ROUTER_IP  — IP роутера для матчинга (по умолчанию 10.70.138.245)
    TEST_HOSTNAME   — имя хоста Zabbix
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
def _pyrus_matcher_real(settings):
    """Реестр Pyrus тем же путём, что и в проде (scheduler._build_matcher):
    креды берём из Settings (config.py), а не из os.environ."""
    from matcher import RegistryMatcher
    from pyrus import PyrusClient, PyrusSiteParser

    client = PyrusClient()
    tasks  = client.get_registry(settings.pyrus_form_id, settings.pyrus_login, settings.pyrus_token)
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
            router_ip="10.70.138.245",   # management-IP железки из Zabbix = ключ матчинга
            address="г. Саратов, Рабочая ул дом №145а",
            city="Саратов",
            channels=[
                ChannelInfo(provider="ТТК", channel_id="TTK-L2VPN-1", bandwidth=100000,
                            contract="ДГ-2024/00567", ip_address="10.70.138.245", technology="L2VPN"),
                ChannelInfo(provider="ТТК", channel_id="TTK-NET-1", bandwidth=50000,
                            contract="ДГ-2024/00999", ip_address="10.70.138.246", technology="Интернет"),
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


def _dump_site(site) -> None:
    """Печатает данные задачи, реально полученные из Pyrus."""
    print(f"        task_id        : {site.task_id}")
    print(f"        дирекция       : {site.directorate}")
    print(f"        zabbix_hostname: {site.zabbix_hostname}")
    print(f"        router_ip      : {site.router_ip}")
    print(f"        адрес          : {site.address}")
    print(f"        каналов        : {len(site.channels)}")
    for ch in site.channels:
        print(f"          • провайдер={ch.provider} | услуга={ch.technology} | "
              f"договор={ch.contract} | {ch.bandwidth} Кбит/с")


# ───────────────────────── Прогон сценария ─────────────────────────────────
def main() -> int:
    _ensure_jnpr()

    from pipeline import run as run_pipeline
    from notifier import build_notification
    from report import print_incident_reports
    from trigger_parser import find_channel_by_trigger

    # «Полученные данные» — то, что приходит из Zabbix-алерта и дальше служит
    # ключом для похода в Pyrus. IP — management-адрес железки.
    device_ip = os.environ.get("TEST_ROUTER_IP", "10.70.138.245")
    hostname  = os.environ.get("TEST_HOSTNAME",  "uk-srt-rabochaya145a-r")

    offline = os.environ.get("SCENARIO_OFFLINE") == "1"

    print("=" * 70)
    print("СЦЕНАРИЙ: обработка RPM-алерта")
    print(f"Полученные данные: trigger={TRIGGER_NAME!r}")
    print(f"                   device_ip={device_ip}  host={hostname}")
    print("=" * 70)

    if offline:
        print("\n[Pyrus] OFFLINE (SCENARIO_OFFLINE=1) — синтетический реестр, БЕЗ похода на сервер")
        matcher, sites = _pyrus_matcher_offline()
    else:
        # Креды Pyrus — из Settings (config.py), тот же источник (.env), что и в
        # проде (scheduler._build_matcher). Никаких os.environ напрямую.
        from config import Settings
        try:
            settings = Settings()
        except Exception as exc:
            print("\n[ОШИБКА] Не удалось загрузить настройки через Settings (config.py / .env):")
            print(f"         {exc}")
            print("         Заполните .env (ZABBIX_*, PYRUS_*) либо запустите с SCENARIO_OFFLINE=1.")
            return 2
        if not (settings.pyrus_login and settings.pyrus_token and settings.pyrus_form_id):
            print("\n[ОШИБКА] В Settings нет кредов Pyrus (PYRUS_LOGIN/PYRUS_TOKEN/PYRUS_FORM_ID).")
            print("         Добавьте их в .env — Settings читает оттуда. Либо SCENARIO_OFFLINE=1.")
            return 2
        from pyrus import PyrusClient
        print(f"\n[Pyrus] РЕАЛЬНЫЙ сервер: {PyrusClient.BASE_URL}  (форма {settings.pyrus_form_id})")
        matcher, sites = _pyrus_matcher_real(settings)

    with_ip = sum(1 for s in sites if s.ip_key)
    uk      = sum(1 for s in sites if s.is_uk)
    print(f"[Pyrus] реестр получен: задач {len(sites)} | c IP роутера {with_ip} | УК-* {uk}")

    # ── Главный шаг: по полученному IP идём в Pyrus и забираем данные задачи ──
    print(f"\n[Pyrus] ищу задачу по «IP-адрес роутера узла сети» = {device_ip} …")
    site = matcher.find(device_ip)
    if site is None:
        print(f"[Pyrus] задача с IP {device_ip} НЕ найдена — проверьте, что поле в Pyrus заполнено.")
    else:
        print("[Pyrus] задача найдена, данные из Pyrus:")
        _dump_site(site)
        ch = find_channel_by_trigger(TRIGGER_NAME, site)
        print(f"[Pyrus] канал под услугу l2vpn провайдера ТТК: "
              + (f"договор={ch.contract}" if ch else "не найден → договор будет «—»"))

    # ── Полный прогон пайплайна (Zabbix синт. + Junos синт. + реальный Pyrus) ─
    problem = _synthetic_problem(TRIGGER_NAME, device_ip, hostname)
    print(f"\n[Zabbix] синтетический RpmProblem: host={problem.host_name} ip={problem.ip} "
          f"cod={problem.cod_name} provider={problem.provider}")

    junos = _synthetic_junos(problem)
    zapi  = _FakeZabbixApi([problem])
    reports = run_pipeline(zapi, junos, matcher)

    print_incident_reports(reports)

    for r in reports:
        print("─" * 70)
        msg = build_notification(r)
        print("--- СООБЩЕНИЕ ОПЕРАТОРУ ---")
        print(msg if msg else "(для этого решения сообщение не формируется)")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
