from __future__ import annotations

import re

from models import ChannelInfo, PyrusSite
from providers import normalize_provider

# Типы канала в имени триггера (а не провайдеры). "inet" — трафик через
# интернет по белым IP (без выделенного L2VPN и без конкретного оператора).
_CHANNEL_TYPES = frozenset({"l2vpn", "ipsec", "inet"})

# Тип канала из триггера → услуга (колонка «Услуга» в Pyrus).
_TYPE_TO_SERVICE = {"inet": "интернет"}

# "RPM потери до m1-ttk-l2vpn - 100 %"  → узел m1, провайдер ttk, тип l2vpn
# "RPM потери до m1-inet - 100 %"       → узел m1, без провайдера, тип inet
_SPEC_RE = re.compile(r'до\s+(?P<spec>\S+)', re.IGNORECASE)
_LOSS_RE = re.compile(r'(\d+(?:[.,]\d+)?)\s*%')


class TriggerInfo:
    """Распарсенный триггер Zabbix: узел, (опц.) провайдер, тип канала."""

    def __init__(self, raw: str) -> None:
        self.raw          = raw
        self.node:         str | None   = None
        self.provider_raw: str | None   = None
        self.provider:     str | None   = None   # нормализованный, напр. "ТТК"
        self.channel_type: str | None   = None   # l2vpn / inet / ipsec
        self.loss_pct:     float | None = None   # % потерь из имени триггера
        self.channel_spec: str | None   = None   # "m1-rtk-l2vpn" — как в ключах item'ов Zabbix

        m = _SPEC_RE.search(raw)
        if m:
            self.channel_spec = m.group("spec")
            parts = [p for p in m.group("spec").split("-") if p]
            if parts:
                self.node = parts[0]
                rest = parts[1:]
                # Последний сегмент — тип канала, если это известный тип.
                if rest and rest[-1].lower() in _CHANNEL_TYPES:
                    self.channel_type = rest[-1].lower()
                    rest = rest[:-1]
                # Что осталось между узлом и типом — провайдер (для inet его нет).
                if rest:
                    self.provider_raw = rest[0]
                    self.provider     = normalize_provider(rest[0])

        m_loss = _LOSS_RE.search(raw)
        if m_loss:
            self.loss_pct = float(m_loss.group(1).replace(",", "."))

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

    Договор должен соответствовать провайдеру (если он есть в триггере) и
    типу услуги. Алгоритм:
      1. Если в триггере есть провайдер ("ttk" → "ТТК") — оставляем каналы
         только этого провайдера. Для inet-триггеров провайдера нет.
      2. Тип канала из триггера сопоставляем с колонкой «Услуга»:
         l2vpn → «L2VPN», inet → «Интернет». Берём канал с этой услугой.
      3. Если тип не указан — подставляем договор только при единственном
         подходящем канале (иначе выбор неоднозначен).
    """
    trigger = TriggerInfo(trigger_name)
    if not site.channels:
        return None

    matches = list(site.channels)

    # 1. Фильтр по провайдеру (у inet-триггера провайдера нет — пропускаем).
    if trigger.provider:
        matches = [
            ch for ch in matches
            if normalize_provider(ch.provider) == trigger.provider
        ]
        if not matches:
            return None

    # 2. Фильтр по услуге, соответствующей типу канала из триггера.
    if trigger.channel_type:
        want = _TYPE_TO_SERVICE.get(trigger.channel_type, trigger.channel_type)
        typed = [ch for ch in matches if ch.service and want in ch.service.lower()]
        return typed[0] if typed else None

    # 3. Тип не распознан — только если канал однозначен.
    return matches[0] if len(matches) == 1 else None
