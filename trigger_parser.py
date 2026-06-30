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

    Договор для сообщения должен соответствовать и провайдеру, и типу
    услуги (l2vpn). Алгоритм:
      1. Нормализуем провайдер из имени триггера ("ttk" → "ТТК").
      2. Оставляем каналы того же провайдера.
      3. Если в триггере указан тип услуги (l2vpn/ipsec) — берём только
         канал с этой услугой; иначе договор не подставляем.
      4. Если тип услуги в триггере не указан — подставляем договор только
         при единственном канале провайдера (иначе выбор неоднозначен).
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

    # Тип услуги из триггера (l2vpn) — обязательное условие: подставляем
    # договор только того канала, чья услуга совпадает. Чужой договор
    # (напр. интернет-канал того же провайдера) не используем.
    if trigger.channel_type:
        typed = [
            ch for ch in matches
            if ch.technology and trigger.channel_type.lower() in ch.technology.lower()
        ]
        return typed[0] if typed else None

    return matches[0] if len(matches) == 1 else None
