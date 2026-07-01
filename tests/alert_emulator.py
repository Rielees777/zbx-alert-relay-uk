"""
tests/alert_emulator.py — разовый прогон JSON-файла с эмулированными
алертами через настоящий пайплайн, с выводом в консоль (без бота).

Использует общую логику из emulator.py — ту же, что применяет scheduler.py
в режиме EMULATOR_FIXTURE. Схема JSON и все детали — см. docstring
emulator.py.

Запуск:
    python tests/alert_emulator.py                        # DEFAULT_FIXTURE
    python tests/alert_emulator.py tests/fixtures/x.json   # свой файл
    python tests/alert_emulator.py ../dev_alerts.json      # общий рабочий файл
"""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

DEFAULT_FIXTURE = os.path.join(_REPO_ROOT, "tests", "fixtures", "alert_partial_loss.json")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FIXTURE
    if not os.path.isfile(path):
        print(f"[ОШИБКА] файл фикстуры не найден: {path}")
        return 2

    from emulator import load_fixture, load_emulated_apis
    import pipeline
    from notifier import build_notification
    from report import print_incident_reports

    fixture = load_fixture(path)

    print("=" * 70)
    print(f"ЭМУЛЯТОР АЛЕРТА — файл: {path}")
    if notes := fixture.get("_readme"):
        print(f"Описание: {notes}")
    print(f"Алертов в файле: {len(fixture.get('alerts', []))}")
    print("=" * 70)

    zabbix_api, junos_api, matcher = load_emulated_apis(path)

    for i, alert in enumerate(fixture.get("alerts", []), 1):
        if notes := alert.get("notes"):
            print(f"\n[{i}] {notes}")

    reports = pipeline.run(zabbix_api, junos_api, matcher)
    print_incident_reports(reports)

    for r in reports:
        print("─" * 70)
        if matcher:
            print(f"[Pyrus] matched: {'task:' + str(r.pyrus_site.task_id) if r.pyrus_site else 'НЕ найдено'}")
        msg = build_notification(r)
        print("--- СООБЩЕНИЕ ОПЕРАТОРУ ---")
        print(msg if msg else "(для этого decision сообщение не формируется)")
        print()

    if not reports:
        print("\n(инциденты отфильтрованы ДО обработки — см. ALLOWED_CHANNEL_TYPES в const.py, "
              "или пустой список alerts)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
