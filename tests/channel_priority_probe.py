"""
tests/channel_priority_probe.py — обход каналов связи узла по приоритету
с пингом каждого, для проверки стратегии переключения на site-алертах
(«Потери до <площадка>»).

Контекст: для site-алерта конкретный канал в триггере не указан, поэтому
стратегия переключения — перебор всех каналов узла в порядке приоритета
(P1, P2, …, с учётом приоритетных BGP-групп const.PRIORITY_BGP_GROUPS) и
пинг каждого, чтобы понять, какие живы, а какие деградировали. Этот
скрипт — только диагностика (см. подробности «отдельный скрипт, попробую
его на железе» в переписке): читает BGP-конфиг и пингует, КОНФИГУРАЦИЮ
УСТРОЙСТВА НЕ МЕНЯЕТ. Как только стратегия подтвердится на реальном
железе — логику можно будет перенести в JunosApi/pipeline.

Использует ту же логику разбора и сортировки каналов, что и боевой
list_bgp_channels (JunosApi._read_bgp_config + BgpChannelParser), и тот
же пингер (JunosPinger), что analyze_problem/analyze_ipsec — никакой
новой логики выявления потерь тут нет, только последовательный обход.

Креды Junos (JUNOS_USER, JUNOS_PASSWORD, …) берутся из Settings (.env).
Тестовые входные данные — переменные ниже, правьте прямо в этом файле.

Запуск:
    python tests/channel_priority_probe.py
"""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)


# ───────────────────────── ТЕСТОВЫЕ ВХОДНЫЕ ДАННЫЕ ─────────────────────────
TEST_HOST_IP:    str = "10.70.138.245"   # management IP узла — правьте под своё железо
TEST_PING_COUNT: int = 20                # пакетов на канал (меньше боевых 100 — обход быстрее)
# ───────────────────────────────────────────────────────────────────────────


def main() -> int:
    from config import Settings
    from const import PRIORITY_BGP_GROUPS
    from junos.api import JunosApi
    from junos.pinger import JunosPinger
    from junos.switcher import BgpChannelParser
    from models import L2vpnLink

    try:
        settings = Settings()
    except Exception as exc:
        print("[ОШИБКА] Не удалось загрузить настройки через Settings (config.py / .env):")
        print(f"         {exc}")
        return 2
    if not (settings.junos_user and settings.junos_password):
        print("[ОШИБКА] В Settings нет кредов Junos (JUNOS_USER/JUNOS_PASSWORD).")
        return 2

    japi = JunosApi(settings)

    print(f"[Junos] подключаюсь к {TEST_HOST_IP} …")
    with japi._connect(TEST_HOST_IP) as dev:
        cfg_xml  = JunosApi._read_bgp_config(dev)
        channels = BgpChannelParser(cfg_xml).channels(priority_groups=PRIORITY_BGP_GROUPS)

        if not channels:
            print("[Junos] в BGP-конфиге не нашлось ни одного канала (соседа).")
            return 1

        print(f"[Junos] каналов найдено: {len(channels)} (порядок — по приоритету: "
              f"{', '.join(PRIORITY_BGP_GROUPS) or '—'} выше остальных, внутри группы P1..Pn)\n")
        print(f"  {'группа':<14} {'приор.':<7} {'описание':<30} {'сосед':<16} результат пинга")
        print("  " + "-" * 90)

        pinger  = JunosPinger(dev)
        results: list[tuple] = []   # (BgpChannel, PingResult | None, ошибка | None)

        for c in channels:
            link = L2vpnLink(
                interface=f"bgp:{c.group}",
                description=c.description or "",
                local_ip=c.local_address or "",
                remote_ip=c.neighbor,
            )
            res, err = None, None
            try:
                res = pinger.ping_link(link, count=TEST_PING_COUNT)
                status = "OK" if not res.has_loss else f"ПОТЕРИ {res.loss}/{TEST_PING_COUNT}"
            except Exception as exc:
                err = str(exc)
                status = f"ОШИБКА: {err}"

            prio = f"P{c.priority}" if c.priority else "P?"
            print(f"  {c.group:<14} {prio:<7} {(c.description or '—'):<30} {c.neighbor:<16} {status}")
            results.append((c, res, err))

    # ── Итог: кто сейчас основной и кто первый доступный кандидат ниже ──────
    print()
    current_c, current_res, current_err = results[0]
    current_ok = current_res is not None and not current_res.has_loss
    print(f"[Итог] текущий (высший приоритет): {current_c.group}/{current_c.description or current_c.neighbor} "
          f"— {'OK' if current_ok else ('ошибка: ' + current_err if current_err else 'ПОТЕРИ')}")

    candidate = next(
        (c for c, res, err in results[1:] if res is not None and not res.has_loss),
        None,
    )
    if current_ok:
        print("[Итог] текущий канал живой — переключение не требуется.")
    elif candidate:
        print(f"[Итог] кандидат на переключение (первый доступный ниже по приоритету): "
              f"{candidate.group}/{candidate.description or candidate.neighbor} (P{candidate.priority or '?'})")
    else:
        print("[Итог] текущий канал недоступен, и ни один канал ниже по приоритету тоже не отвечает.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
