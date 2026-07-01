"""
tests/zabbix_util_probe.py — пробное подключение к Zabbix и сбор данных
утилизации интерфейса.

Цель: понять на реальных данных, в каких единицах Zabbix хранит трафик
интерфейса, как достать пик за окно (по умолчанию 20 мин) и как сравнить его
с шириной канала из таблицы каналов связи Pyrus (Кбит/с).

Скрипт ничего не меняет — только читает. «График» утилизации в Zabbix — это
визуализация item'ов трафика; здесь мы запрашиваем те же item'ы и их историю
напрямую через API.

Все параметры можно задавать И в .env, И при запуске — значения, указанные
при запуске (в окружении), имеют приоритет над .env.

Креды Zabbix (обязательны, их грузит Settings):
    ZABBIX_URL, ZABBIX_TOKEN

Цель (что смотрим) — одно из:
    ZBX_HOSTID=10456                    # напрямую hostid
    ZBX_HOST="Алтай - Чепош"            # видимое имя хоста
    TEST_ROUTER_IP=10.70.138.98         # IP интерфейса хоста

Необязательно:
    UTIL_MINUTES=20                     # окно анализа (по умолчанию 20)
    BANDWIDTH_KBPS=100000               # ширина канала из Pyrus, для расчёта %
    ITEM_KEY_FILTER=net.if              # подстрока ключа item'а (по умолчанию net.if)

Запуск (параметры в .env):
    python tests/zabbix_util_probe.py

Запуск (параметры при вызове):
    ZBX_HOST="Алтай - Чепош" BANDWIDTH_KBPS=100000 python tests/zabbix_util_probe.py
"""

from __future__ import annotations

import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)


def _load_dotenv() -> None:
    """Подхватывает переменные из .env в окружение процесса, чтобы параметры
    теста (ZBX_HOST, BANDWIDTH_KBPS и т.п.) можно было держать и в .env.
    Значения, заданные при запуске, приоритетнее (setdefault их не трогает).
    Заодно позволяет Settings найти креды из любого каталога запуска."""
    path = os.path.join(_REPO_ROOT, ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def _fmt_bps(bps: float) -> str:
    """bps → человекочитаемо (Кбит/с, Мбит/с)."""
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Мбит/с"
    if bps >= 1_000:
        return f"{bps / 1_000:.2f} Кбит/с"
    return f"{bps:.0f} бит/с"


def _resolve_hostid(zapi) -> str | None:
    """Определяет hostid по ZBX_HOSTID / ZBX_HOST / TEST_ROUTER_IP."""
    if hostid := os.environ.get("ZBX_HOSTID"):
        return hostid

    if name := os.environ.get("ZBX_HOST"):
        hosts = zapi.host.get(output=["hostid", "host", "name"],
                              search={"name": name}, searchWildcardsEnabled=True)
        if not hosts:
            hosts = zapi.host.get(output=["hostid", "host", "name"], filter={"host": name})
        if hosts:
            print(f"[host] по имени {name!r} найдено: "
                  + ", ".join(f"{h['name']}(hostid={h['hostid']})" for h in hosts))
            return hosts[0]["hostid"]
        print(f"[host] по имени {name!r} ничего не найдено")
        return None

    if ip := os.environ.get("TEST_ROUTER_IP"):
        ifaces = zapi.hostinterface.get(output=["hostid", "ip"], filter={"ip": ip})
        if ifaces:
            return ifaces[0]["hostid"]
        print(f"[host] по IP {ip} интерфейс не найден")
        return None

    print("[host] задайте ZBX_HOSTID, ZBX_HOST или TEST_ROUTER_IP")
    return None


def _history_stats(zapi, item: dict, minutes: int) -> dict | None:
    """История item'а за окно → min/avg/max/last (сырые значения)."""
    value_type = int(item["value_type"])
    time_from  = int(time.time()) - minutes * 60
    hist = zapi.history.get(
        itemids=[item["itemid"]],
        time_from=time_from,
        history=value_type,
        output="extend",
        sortfield="clock",
        sortorder="ASC",
    )
    values = [float(h["value"]) for h in hist]
    if not values:
        return None
    return {
        "count": len(values),
        "min":   min(values),
        "avg":   sum(values) / len(values),
        "max":   max(values),
        "last":  values[-1],
    }


def main() -> int:
    _load_dotenv()

    from config import Settings
    from zabbix import ZabbixApi

    try:
        settings = Settings()
    except Exception as exc:
        print("[ОШИБКА] не удалось загрузить Settings (config.py / .env):")
        print(f"         {exc}")
        print("         Заполните .env: ZABBIX_URL, ZABBIX_TOKEN")
        return 2

    minutes    = int(os.environ.get("UTIL_MINUTES", "20"))
    key_filter = os.environ.get("ITEM_KEY_FILTER", "net.if")
    bw_kbps    = os.environ.get("BANDWIDTH_KBPS")
    bw_kbps    = int(bw_kbps) if bw_kbps else None

    print("=" * 70)
    print("ZABBIX UTIL PROBE — сбор данных утилизации интерфейса")
    print(f"Окно: {minutes} мин | фильтр ключа item'а: {key_filter!r}"
          + (f" | ширина канала: {bw_kbps} Кбит/с" if bw_kbps else ""))
    print("=" * 70)

    with ZabbixApi(settings.zabbix_config()) as z:
        zapi = z._zapi  # pyzabbix ZabbixAPI

        hostid = _resolve_hostid(zapi)
        if not hostid:
            return 1

        host = zapi.host.get(output=["hostid", "host", "name"], hostids=[hostid])
        if host:
            print(f"\n[host] hostid={hostid} host={host[0]['host']!r} name={host[0]['name']!r}")

        # 1. Item'ы трафика интерфейса
        items = zapi.item.get(
            hostids=[hostid],
            output=["itemid", "key_", "name", "units", "value_type", "lastvalue", "lastclock"],
            search={"key_": key_filter},
            sortfield="key_",
        )
        if not items:
            print(f"\n[item] по фильтру {key_filter!r} ничего не найдено — "
                  "попробуйте другой ITEM_KEY_FILTER (напр. 'ifHCIn', 'traffic', 'bits').")
            return 1

        print(f"\n[item] найдено {len(items)} item'ов (itemid | units | value_type | lastvalue | key_):")
        for it in items:
            print(f"    {it['itemid']:>8} | {it.get('units',''):>6} | vt={it['value_type']} | "
                  f"last={it.get('lastvalue','')!s:>14} | {it['key_']}")
            print(f"             name: {it.get('name','')}")

        # 2. История за окно + пик по каждому item'у
        print(f"\n[history] статистика за последние {minutes} мин (сырые значения item'а):")
        peak_overall = 0.0
        peak_units   = ""
        for it in items:
            st = _history_stats(zapi, it, minutes)
            if not st:
                print(f"    itemid={it['itemid']} {it['key_']}: нет данных за окно")
                continue
            u = it.get("units", "")
            print(f"    {it['key_']}  [{u}]")
            print(f"        точек={st['count']}  min={st['min']:.2f}  avg={st['avg']:.2f}  "
                  f"max(пик)={st['max']:.2f}  last={st['last']:.2f}")
            # для расчёта утилизации ориентируемся на bps-метрики
            if u in ("bps", "bits/s", "b/s") or "bps" in (it.get("name", "").lower()):
                if st["max"] > peak_overall:
                    peak_overall = st["max"]
                    peak_units   = u

        # 3. Расчёт утилизации относительно ширины канала
        print("\n[util] расчёт утилизации:")
        if peak_overall <= 0:
            print("    Не удалось однозначно определить bps-пик — сверьте units item'ов выше.")
            print("    Утилизация% = пик_bps / (ширина_Кбит/с × 1000) × 100")
        else:
            print(f"    Пик трафика: {peak_overall:.0f} [{peak_units}]  ({_fmt_bps(peak_overall)})")
            if bw_kbps:
                bw_bps = bw_kbps * 1000
                util   = peak_overall / bw_bps * 100
                print(f"    Ширина канала (Pyrus): {bw_kbps} Кбит/с ({_fmt_bps(bw_bps)})")
                print(f"    Утилизация в пике: {util:.1f}%")
                verdict = ("ПЕРЕГРУЗКА канала (>90%)" if util > 90
                           else "канал НЕ перегружен (<90%) → вероятно, проблема у оператора")
                print(f"    Вывод: {verdict}")
            else:
                print("    Задайте BANDWIDTH_KBPS, чтобы посчитать % (ширину берём из таблицы Pyrus).")

        # 4. Подсказка по метрикам скорости интерфейса (для сверки с Pyrus)
        speed = zapi.item.get(
            hostids=[hostid],
            output=["itemid", "key_", "name", "units", "lastvalue"],
            search={"key_": "speed"},
        )
        if speed:
            print("\n[speed] item'ы скорости интерфейса (сверить с шириной из Pyrus):")
            for it in speed:
                print(f"    {it['key_']}  units={it.get('units','')}  last={it.get('lastvalue','')}  "
                      f"({it.get('name','')})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
