"""
tests/zabbix_util_probe.py — пробное подключение к Zabbix и сбор данных
утилизации интерфейса.

Цель: понять на реальных данных, в каких единицах Zabbix хранит трафик
интерфейса, как достать пик за окно (по умолчанию 20 мин) и как сравнить его
с шириной канала из таблицы каналов связи Pyrus (Кбит/с).

Скрипт ничего не меняет — только читает. «График» утилизации в Zabbix — это
визуализация item'ов трафика; здесь мы запрашиваем те же item'ы и их историю
напрямую через API.

Креды Zabbix (ZABBIX_URL, ZABBIX_TOKEN) берутся из Settings (.env).
Тестовые входные данные задаются переменными ниже (блок «ТЕСТОВЫЕ ВХОДНЫЕ
ДАННЫЕ») — правьте прямо в этом файле.

Запуск:
    python tests/zabbix_util_probe.py
"""

from __future__ import annotations

import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)


# ───────────────────────── ТЕСТОВЫЕ ВХОДНЫЕ ДАННЫЕ ─────────────────────────
# Правьте значения здесь. Цель (что смотрим) — достаточно ОДНОГО из трёх,
# приоритет: HOSTID → HOST → ROUTER_IP.
TEST_HOSTID:     str | None = None                 # напрямую hostid, напр. "10456"
TEST_HOST:       str | None = "Алтай - Чепош"      # видимое имя хоста в Zabbix
TEST_ROUTER_IP:  str | None = None                 # IP интерфейса хоста, напр. "10.70.138.98"

TEST_UTIL_MINUTES:    int        = 20              # окно анализа, минут
TEST_BANDWIDTH_KBPS:  int | None = None            # ширина канала из Pyrus, Кбит/с (для %)

# Подстрока ключа item'а. На реальном Zabbix трафик по каналу связи хранится
# в кастомных item'ах "isp.*", где параметр в скобках — это ТА ЖЕ подстрока,
# что идёт после "RPM потери до " в имени триггера (напр. триггер
# "RPM потери до m1-rtk-l2vpn - 100 %" → item'ы "isp.bandwidth.[m1-rtk-l2vpn]",
# "isp.calc.in.[m1-rtk-l2vpn]", "rpm.loss.[m1-rtk-l2vpn]" и т.п.).
# Поставьте здесь именно эту подстроку из интересующего триггера.
# Если не уверены — поставьте None: скрипт выведет СПИСОК ВСЕХ item'ов хоста
# (только key_/name/units, без истории), чтобы найти нужный канал.
TEST_ITEM_KEY_FILTER: str | None = "m1-rtk-l2vpn"
# ───────────────────────────────────────────────────────────────────────────


def _fmt_bps(bps: float) -> str:
    """bps → человекочитаемо (Кбит/с, Мбит/с)."""
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Мбит/с"
    if bps >= 1_000:
        return f"{bps / 1_000:.2f} Кбит/с"
    return f"{bps:.0f} бит/с"


def _resolve_hostid(zapi) -> str | None:
    """Определяет hostid по TEST_HOSTID / TEST_HOST / TEST_ROUTER_IP."""
    if TEST_HOSTID:
        return TEST_HOSTID

    if TEST_HOST:
        hosts = zapi.host.get(output=["hostid", "host", "name"],
                              search={"name": TEST_HOST}, searchWildcardsEnabled=True)
        if not hosts:
            hosts = zapi.host.get(output=["hostid", "host", "name"], filter={"host": TEST_HOST})
        if hosts:
            print(f"[host] по имени {TEST_HOST!r} найдено: "
                  + ", ".join(f"{h['name']}(hostid={h['hostid']})" for h in hosts))
            return hosts[0]["hostid"]
        print(f"[host] по имени {TEST_HOST!r} ничего не найдено")
        return None

    if TEST_ROUTER_IP:
        ifaces = zapi.hostinterface.get(output=["hostid", "ip"], filter={"ip": TEST_ROUTER_IP})
        if ifaces:
            return ifaces[0]["hostid"]
        print(f"[host] по IP {TEST_ROUTER_IP} интерфейс не найден")
        return None

    print("[host] задайте TEST_HOSTID, TEST_HOST или TEST_ROUTER_IP в начале файла")
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
    from config import Settings
    from zabbix import ZabbixApi

    try:
        settings = Settings()
    except Exception as exc:
        print("[ОШИБКА] не удалось загрузить Settings (config.py / .env):")
        print(f"         {exc}")
        print("         Заполните .env: ZABBIX_URL, ZABBIX_TOKEN")
        return 2

    minutes    = TEST_UTIL_MINUTES
    key_filter = TEST_ITEM_KEY_FILTER
    bw_kbps    = TEST_BANDWIDTH_KBPS

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

        # Режим обнаружения: TEST_ITEM_KEY_FILTER не задан — печатаем ВСЕ
        # item'ы хоста (без истории), чтобы найти реальные ключи трафика и
        # подставить нужную подстроку в TEST_ITEM_KEY_FILTER.
        if not key_filter:
            all_items = zapi.item.get(
                hostids=[hostid],
                output=["itemid", "key_", "name", "units", "value_type"],
                sortfield="key_",
            )
            print(f"\n[discovery] TEST_ITEM_KEY_FILTER не задан — все item'ы хоста ({len(all_items)}):")
            print("            (itemid | units | vt | key_ — name)")
            for it in all_items:
                print(f"    {it['itemid']:>8} | {it.get('units','') or '-':>6} | vt={it['value_type']} | "
                      f"{it['key_']}  —  {it.get('name','')}")
            print("\n[discovery] найдите строки с трафиком интерфейса (обычно 'in'/'out', "
                  "'octets', 'bits', 'traffic') и укажите общую подстроку их ключей "
                  "в TEST_ITEM_KEY_FILTER, затем запустите скрипт снова.")
            return 0

        # 1. Item'ы трафика интерфейса
        items = zapi.item.get(
            hostids=[hostid],
            output=["itemid", "key_", "name", "units", "value_type", "lastvalue", "lastclock"],
            search={"key_": key_filter},
            sortfield="key_",
        )
        if not items:
            print(f"\n[item] по фильтру {key_filter!r} ничего не найдено — "
                  "поставьте TEST_ITEM_KEY_FILTER = None для просмотра всех item'ов хоста.")
            return 1

        print(f"\n[item] найдено {len(items)} item'ов (itemid | units | value_type | lastvalue | key_):")
        for it in items:
            print(f"    {it['itemid']:>8} | {it.get('units',''):>6} | vt={it['value_type']} | "
                  f"last={it.get('lastvalue','')!s:>14} | {it['key_']}")
            print(f"             name: {it.get('name','')}")

        # 2. Категоризация по ключу. Проверено на реальных данных (см. историю):
        # "isp.bandwidth.[chan]" — item ОДИН на канал и АБСОЛЮТНО СТАТИЧЕН
        # (min=avg=max за 20 мин) → это НОМИНАЛЬНАЯ ШИРИНА канала (ёмкость),
        # а не факт. трафик. "isp.speed.in/out.[chan]" — колеблются во
        # времени по обоим направлениям → это и есть ФАКТИЧЕСКИЙ ТРАФИК.
        # Проверка: isp.speed.{in,out} / isp.bandwidth × 100 совпало с
        # isp.calc.{in,out} (0.003% округлилось в 0 — как и есть в calc).
        def _category(key: str) -> str:
            if "rpm.loss" in key:
                return "rpm_loss"
            if ".calc." in key:
                return "calc_pct"       # уже готовый % утилизации (isp.calc.in/out)
            if ".speed." in key:
                return "traffic_bps"    # фактический трафик по направлениям (in/out)
            if "bandwidth" in key:
                return "capacity_bps"   # номинальная ширина (ёмкость) канала
            return "other"

        print(f"\n[history] статистика за последние {minutes} мин (сырые значения item'а):")
        stats_by_cat: dict[str, list[tuple[dict, dict]]] = {}
        for it in items:
            st = _history_stats(zapi, it, minutes)
            cat = _category(it["key_"])
            if not st:
                print(f"    [{cat}] {it['key_']}: нет данных за окно")
                continue
            stats_by_cat.setdefault(cat, []).append((it, st))
            u = it.get("units", "")
            print(f"    [{cat}] {it['key_']}  [{u}]")
            print(f"        точек={st['count']}  min={st['min']:.2f}  avg={st['avg']:.2f}  "
                  f"max(пик)={st['max']:.2f}  last={st['last']:.2f}")

        # 3. Утилизация — два независимых способа, для сверки друг с другом.
        print("\n[util] расчёт утилизации:")

        # 3a. Готовый % от самого Zabbix (isp.calc.in/out), если такие item'ы есть.
        calc_items = stats_by_cat.get("calc_pct", [])
        if calc_items:
            calc_peak = max(st["max"] for _, st in calc_items)
            print(f"    [готовый %] max(isp.calc.in/out) за окно: {calc_peak:.1f}%  "
                  "(уже посчитано в Zabbix — сверить с расчётом вручную ниже)")
        else:
            calc_peak = None
            print("    [готовый %] item'ов isp.calc.* с этим фильтром не найдено.")

        # 3b. Расчёт вручную: факт. трафик (isp.speed.in/out) / ширину канала
        # (isp.bandwidth, либо TEST_BANDWIDTH_KBPS из Pyrus, если задан).
        traffic_items  = stats_by_cat.get("traffic_bps", [])
        capacity_items = stats_by_cat.get("capacity_bps", [])
        if traffic_items:
            traffic_peak = max(st["max"] for _, st in traffic_items)
            print(f"    [вручную]  пик трафика (isp.speed.in/out): {traffic_peak:.0f} bps "
                  f"({_fmt_bps(traffic_peak)})")

            # Ширина: приоритет TEST_BANDWIDTH_KBPS (из Pyrus), иначе isp.bandwidth.
            bw_bps_ref = None
            ref_src    = ""
            if bw_kbps:
                bw_bps_ref = bw_kbps * 1000
                ref_src    = f"Pyrus, TEST_BANDWIDTH_KBPS={bw_kbps} Кбит/с"
            elif capacity_items:
                bw_bps_ref = max(st["last"] for _, st in capacity_items)
                ref_src    = "isp.bandwidth (last)"

            if bw_bps_ref:
                util = traffic_peak / bw_bps_ref * 100
                print(f"    [вручную]  ширина канала: {bw_bps_ref:.0f} bps ({_fmt_bps(bw_bps_ref)})  "
                      f"[источник: {ref_src}]")
                print(f"    [вручную]  утилизация в пике: {util:.1f}%")
                verdict = ("ПЕРЕГРУЗКА канала (>90%)" if util > 90
                           else "канал НЕ перегружен (<90%) → вероятно, проблема у оператора")
                print(f"    Вывод (вручную): {verdict}")
            else:
                print("    [вручную]  нет ширины канала для сравнения — задайте TEST_BANDWIDTH_KBPS "
                      "или проверьте item isp.bandwidth.")
        else:
            print("    [вручную]  item'ов isp.speed.in/out с этим фильтром не найдено.")

        if capacity_items:
            print("\n[capacity] номинальная ширина канала (сверить с шириной из Pyrus):")
            for it, st in capacity_items:
                print(f"    {it['key_']}  units={it.get('units','')}  last={st['last']:.0f}  "
                      f"({_fmt_bps(st['last'])})")

        rpm_items = stats_by_cat.get("rpm_loss", [])
        if rpm_items:
            print("\n[rpm.loss] потери по данным Zabbix (сверить с ping из junos):")
            for it, st in rpm_items:
                print(f"    {it['key_']}  max(пик)={st['max']:.1f}%  last={st['last']:.1f}%")

        if calc_peak is not None:
            print(f"\n[сверка] готовый %({calc_peak:.1f}) vs вручную посчитанный — "
                  "если совпадают, isp.calc.* можно использовать напрямую без своей формулы.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
