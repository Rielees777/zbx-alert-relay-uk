"""
junos/switcher.py — инвентаризация BGP-каналов связи и (пока отключённое)
переключение основной/резервный.

Приоритет канала задан суффиксом -P<n> в именах политик import/export
соседа: P1 — основной, P2 — резервный, P3/P4 — далее по порядку.
Имена политик могут различаться по группам (eBGP-IN-P1,
eBGP-IN-DC-MOSCOW-P2, eBGP-IN-HUB…) — приоритет берётся из суффикса
import-политики, а если его там нет (напр. eBGP-IN-HUB) — из export.

BgpChannelParser.channels() разбирает ВСЕ группы protocols/bgp и отдаёт
список BgpChannel: группа, IP соседа, описание, политики, приоритет.

Здесь только чистая логика (парсинг конфига + генерация set-команд),
без подключения к устройству — работу с железом делает JunosApi
(junos/api.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Суффикс приоритета в имени политики: eBGP-IN-P3 → 3, eBGP-IN-DC-MOSCOW-P1 → 1
_PRIORITY_RE = re.compile(r"-P(\d+)$", re.IGNORECASE)


@dataclass
class BgpChannel:
    """Один канал связи = BGP-сосед с политиками и приоритетом."""
    group:       str                # имя BGP-группы (ebgp, DC-MOSCOW, …)
    neighbor:    str                # IP соседа
    description: str | None         # напр. "m1-rtk-l2vpn"
    imports:     list[str] = field(default_factory=list)   # группы префиксов import
    exports:     list[str] = field(default_factory=list)   # группы префиксов export
    priority:    int | None = None  # из суффикса -P<n>: 1 — основной, 2 — резервный…

    @property
    def is_primary(self) -> bool:
        return self.priority == 1


def _policy_priority(imports: list[str], exports: list[str]) -> int | None:
    """Приоритет из суффикса -P<n>: сначала ищем в import, затем в export."""
    for name in (*imports, *exports):
        m = _PRIORITY_RE.search(name)
        if m:
            return int(m.group(1))
    return None


@dataclass
class BgpNeighbor:
    address:     str
    description: str | None
    imports:     list[str] = field(default_factory=list)
    exports:     list[str] = field(default_factory=list)


@dataclass
class SwitchPlan:
    """План обмена политиками между двумя соседями."""
    group: str
    a:     BgpNeighbor
    b:     BgpNeighbor

    def commands(self) -> list[str]:
        """Set-команды: у каждого соседа удаляем свои политики и ставим
        политики второго (порядок政策 в цепочке сохраняется)."""
        cmds: list[str] = []
        for n, other in ((self.a, self.b), (self.b, self.a)):
            base = f"protocols bgp group {self.group} neighbor {n.address}"
            if n.imports:
                cmds.append(f"delete {base} import")
            if n.exports:
                cmds.append(f"delete {base} export")
            for p in other.imports:
                cmds.append(f"set {base} import {p}")
            for p in other.exports:
                cmds.append(f"set {base} export {p}")
        return cmds


@dataclass
class SwitchResult:
    """Итог операции переключения (для лога/отчёта/чата)."""
    success:   bool
    dry_run:   bool
    group:     str
    neighbors: tuple[str, str] | None = None   # (адрес A, адрес B)
    commands:  list[str] = field(default_factory=list)
    diff:      str | None = None               # вывод "show | compare"
    error:     str | None = None


class BgpPolicySwitcher:
    """Разбирает XML-конфиг (rpc get-config, ветка protocols/bgp) и строит
    план обмена политиками. Совместим и с lxml, и с xml.etree."""

    def __init__(self, config_xml) -> None:
        self.root = self._strip_ns(config_xml)

    def channels(self) -> list[BgpChannel]:
        """
        Полный список каналов связи по ВСЕМ BGP-группам конфига:
        группа, IP соседа, описание, группы префиксов import/export и
        приоритет из суффикса -P<n> имён политик.
        """
        result: list[BgpChannel] = []
        for grp in self.root.iter("group"):
            group_name = self._text(grp, "name")
            if not group_name:
                continue
            for nb in grp.findall("neighbor"):
                imports = [self._el_text(e) for e in nb.findall("import")]
                exports = [self._el_text(e) for e in nb.findall("export")]
                result.append(BgpChannel(
                    group       = group_name,
                    neighbor    = self._text(nb, "name"),
                    description = self._text(nb, "description") or None,
                    imports     = imports,
                    exports     = exports,
                    priority    = _policy_priority(imports, exports),
                ))
        return result

    def neighbors(self, group: str) -> list[BgpNeighbor]:
        result: list[BgpNeighbor] = []
        for grp in self.root.iter("group"):
            if self._text(grp, "name") != group:
                continue
            for nb in grp.findall("neighbor"):
                result.append(BgpNeighbor(
                    address     = self._text(nb, "name"),
                    description = self._text(nb, "description") or None,
                    imports     = [self._el_text(e) for e in nb.findall("import")],
                    exports     = [self._el_text(e) for e in nb.findall("export")],
                ))
        return result

    def plan_swap(self, group: str = "ebgp", channel_spec: str | None = None) -> SwitchPlan:
        """
        Находит ровно двух соседей группы с настроенными политиками и
        возвращает план их обмена.

        channel_spec (напр. "m1-ttk-l2vpn" из триггера) — защитная проверка:
        если задан, description одного из соседей обязан его содержать —
        иначе мы, вероятно, не на том устройстве/группе, и меняться нельзя.
        """
        with_policies = [
            n for n in self.neighbors(group)
            if n.imports or n.exports
        ]
        if len(with_policies) != 2:
            raise ValueError(
                f"В группе {group!r} найдено {len(with_policies)} соседей с политиками, "
                f"для переключения нужно ровно 2: "
                f"{[n.address for n in with_policies]}"
            )

        a, b = with_policies
        if channel_spec:
            specs = [(n.description or "").lower() for n in (a, b)]
            if not any(channel_spec.lower() in d for d in specs):
                raise ValueError(
                    f"Ни один из соседей ({a.address}: {a.description!r}, "
                    f"{b.address}: {b.description!r}) не соответствует каналу "
                    f"{channel_spec!r} — переключение отменено."
                )
        return SwitchPlan(group=group, a=a, b=b)

    @staticmethod
    def _strip_ns(root):
        for el in root.iter():
            tag = el.tag
            if isinstance(tag, str) and "}" in tag:
                el.tag = tag.split("}", 1)[1]
        return root

    @staticmethod
    def _text(node, tag: str) -> str:
        val = node.findtext(tag)
        return val.strip() if val else ""

    @staticmethod
    def _el_text(el) -> str:
        return (el.text or "").strip()


# Основное имя для инвентаризации каналов; BgpPolicySwitcher оставлено
# как историческое (там же живёт пока отключённый план обмена политик).
BgpChannelParser = BgpPolicySwitcher
