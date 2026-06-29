from __future__ import annotations

import re

from models import ChannelInfo, PyrusSite
from providers import normalize_provider

# "RPM потери до m1-ttk-l2vpn"
#                   ^^  ^^^  ^^^^^
#                 узел  провайдер  тип
_TRIGGER_RE = re.compile(
    r'до\s+(?P<node>[^-\s]+)-(?P<provider>[^-\s]+)(?:-(?P<channel_type>[^-\s]+))?',
    re.IGNORECASE,
)


class TriggerInfo:
    """Распарсенный триггер Zabbix: узел, провайдер, тип канала."""

    def __init__(self, raw: str) -> None:
        self.raw          = raw
        self.node:         str | None = None
        self.provider_raw: str | None = None
        self.provider:     str | None = None   # нормализованный, напр. "ТТК"
        self.channel_type: str | None = None

        m = _TRIGGER_RE.search(raw)
        if m:
            self.node         = m.group("node")
            self.provider_raw = m.group("provider")
            self.provider     = normalize_provider(self.provider_raw)
            self.channel_type = m.group("channel_type")

    def __repr__(self) -> str:
        return (
            f"TriggerInfo(node={self.node!r}, "
            f"provider={self.provider!r}, "
            f"channel_type={self.channel_type!r})"
        )


def find_channel_by_trigger(
    trigger_name: str,
    site: PyrusSite,
) -> ChannelInfo | None:
    """
    По имени триггера находит нужный канал в задаче Pyrus.

    Алгоритм:
      1. Нормализуем провайдер из имени триггера ("ttk" → "ТТК").
      2. Нормализуем провайдер каждого канала Pyrus и сравниваем.
      3. Если нашли несколько каналов одного провайдера — сужаем по типу.
      4. Фолбэк — первый совпавший канал.
    """
    trigger = TriggerInfo(trigger_name)
    if not trigger.provider or not site.channels:
        return None

    matches = [
        ch for ch in site.channels
        if normalize_provider(ch.provider) == trigger.provider
    ]

    if not matches:
        return None

    if len(matches) == 1:
        return matches[0]

    # Несколько каналов одного провайдера — уточняем по типу (l2vpn, ipsec, …)
    if trigger.channel_type:
        narrowed = [
            ch for ch in matches
            if ch.technology and trigger.channel_type.lower() in ch.technology.lower()
        ]
        if narrowed:
            return narrowed[0]

    return matches[0]
