"""
tests/list_providers.py — выгрузка списка провайдеров из реестра каналов
связи (БД) для настройки алиасов в providers.PROVIDER_ALIASES.

Читает весь реестр из PostgreSQL (та же БД/схема, что и в проде — креды
из Settings/.env), собирает все встречающиеся значения провайдера из
таблиц каналов (ChannelInfo.provider, как есть, без нормализации) и
печатает их в консоль: сколько каналов у каждого варианта написания и
распознаётся ли он уже через PROVIDER_ALIASES (providers.py) или нет.
Ничего не меняет — только читает и печатает.

Запуск:
    python tests/list_providers.py
"""

from __future__ import annotations

import os
import sys
from collections import Counter

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)


def main() -> int:
    from config import Settings
    from db import get_connection, load_sites
    from providers import is_aliased, normalize_provider

    try:
        settings = Settings()
    except Exception as exc:
        print("[ОШИБКА] Не удалось загрузить настройки через Settings (config.py / .env):")
        print(f"         {exc}")
        return 2

    try:
        conn = get_connection(settings)
        try:
            sites = load_sites(conn)
        finally:
            conn.close()
    except Exception as exc:
        print(f"[ОШИБКА] Не удалось прочитать реестр из БД (DB_*): {exc}")
        return 2

    counts: Counter[str] = Counter()
    for site in sites:
        for ch in site.channels:
            if ch.provider and ch.provider.strip():
                counts[ch.provider.strip()] += 1

    print(f"Задач в реестре: {len(sites)}")
    if not counts:
        print("Ни одного канала с заполненным провайдером не найдено.")
        return 0
    print(f"Провайдеров (уникальных написаний): {len(counts)}  |  каналов всего: {sum(counts.values())}\n")

    unknown = sorted((raw for raw in counts if not is_aliased(raw)), key=lambda r: -counts[r])
    known   = sorted((raw for raw in counts if is_aliased(raw)),     key=lambda r: -counts[r])

    if unknown:
        print(f"НЕ РАСПОЗНАЮТСЯ ({len(unknown)}) — добавьте в PROVIDER_ALIASES (providers.py):")
        for raw in unknown:
            print(f"    {counts[raw]:>4}  {raw!r}")
        print()

    print(f"Уже распознаются ({len(known)}):")
    for raw in known:
        print(f"    {counts[raw]:>4}  {raw!r:<40} -> {normalize_provider(raw)!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
