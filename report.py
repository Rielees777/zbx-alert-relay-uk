from __future__ import annotations

import datetime as dt

from models import IncidentDecision, IncidentReport

_W   = 64
SEP  = "─" * _W
SEP2 = "═" * _W

_DECISION_LABELS: dict[IncidentDecision, str] = {
    IncidentDecision.CHANNEL_DOWN:     "КАНАЛ НЕДОСТУПЕН — 100% потерь",
    IncidentDecision.HIGH_UTILIZATION: "ВЫСОКАЯ ЗАГРУЗКА КАНАЛА",
    IncidentDecision.DEGRADED_CHANNEL: "ДЕГРАДАЦИЯ КАНАЛА",
    IncidentDecision.IPSEC_LOSS:       "ПОТЕРИ В IPSEC-ТОННЕЛЕ",
    IncidentDecision.FALSE_POSITIVE:   "ЛОЖНОЕ СРАБАТЫВАНИЕ",
    IncidentDecision.ERROR:            "ОШИБКА ПРОВЕРКИ",
}

_ORDER = [
    IncidentDecision.ERROR,
    IncidentDecision.CHANNEL_DOWN,
    IncidentDecision.HIGH_UTILIZATION,
    IncidentDecision.IPSEC_LOSS,
    IncidentDecision.DEGRADED_CHANNEL,
    IncidentDecision.FALSE_POSITIVE,
]


def print_incident_reports(reports: list[IncidentReport]) -> None:
    if not reports:
        print(f"\n{SEP2}\n  Инцидентов для разбора нет.\n{SEP2}")
        return

    by_decision: dict[IncidentDecision | None, list[IncidentReport]] = {}
    for r in reports:
        by_decision.setdefault(r.decision, []).append(r)

    print(f"\n{SEP2}")
    print(f"  Итог проверки: {len(reports)} инцидент(ов)")
    print(SEP2)

    for decision in _ORDER:
        group = by_decision.get(decision, [])
        if not group:
            continue
        label = _DECISION_LABELS.get(decision, str(decision))
        print(f"\n  [{len(group)}] {label}:")
        print(SEP)
        for r in group:
            _print_incident(r)


def _print_incident(r: IncidentReport) -> None:
    p = r.problem
    print(f"\n  Хост : {p.host_name} ({p.ip})")
    print(f"  COD  : {p.cod_name} ({p.cod_ip})")
    print(f"  Алерт: {p.severity_label} с {_fmt_ts(p.started)}")

    if r.error:
        print(f"  ! Ошибка: {r.error}")
        return

    if r.ping_results:
        print(f"  L2VPN:")
        for res in r.ping_results:
            status = f"потери: {res.loss} пак." if res.has_loss else "OK"
            print(f"    {res.interface:<25} {res.local_ip} → {res.remote_ip:<16} {status}")
    else:
        print("  ! L2VPN-линки не найдены на устройстве.")

    if r.utilization_pct is not None:
        print(f"  Утилизация канала: {r.utilization_pct:.1f}%")

    if r.ipsec_results:
        print(f"  IPSEC:")
        for res in r.ipsec_results:
            status = f"потери: {res.loss} пак." if res.has_loss else "OK"
            print(f"    {res.interface:<25} {res.local_ip} → {res.remote_ip:<16} {status}")
    print()


def _fmt_ts(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S") if epoch else "–"
