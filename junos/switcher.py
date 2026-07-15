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

# Типы канала в description соседа. Позиция сегмента различается
# ("m1-rtk-l2vpn", "n11-inet-megafon", "uk-spb-obvod60-l2vpn-obit",
# "m1-df-ix-cortel" — df = тёмное волокно, не последним сегментом),
# поэтому тип ищется среди всех сегментов, а не по позиции.
_CHANNEL_TYPES = frozenset({"l2vpn", "inet", "ipsec", "df"})


@dataclass
class BgpChannel:
    """Один канал связи = BGP-сосед с политиками и приоритетом."""
    group:         str                # имя BGP-группы (ebgp, DC-MOSCOW, …)
    neighbor:      str                # IP соседа
    description:   str | None         # напр. "m1-rtk-l2vpn"
    imports:       list[str] = field(default_factory=list)   # группы префиксов import
    exports:       list[str] = field(default_factory=list)   # группы префиксов export
    priority:      int | None = None  # из суффикса -P<n>: 1 — основной, 2 — резервный…
    group_rank:    int = 0            # приоритет группы: 0 — самая приоритетная
                                      # (PRIORITY_BGP_GROUPS), дальше — ниже
    local_address: str | None = None  # local-address соседа, если задан в конфиге

    @property
    def is_primary(self) -> bool:
        return self.priority == 1

    @property
    def channel_type(self) -> str | None:
        """Тип канала (l2vpn/inet/ipsec) из сегментов description."""
        for seg in (self.description or "").lower().split("-"):
            if seg in _CHANNEL_TYPES:
                return seg
        return None


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
    success:             bool
    dry_run:             bool
    group:               str
    neighbors:           tuple[str, str] | None = None   # (адрес A, адрес B)
    commands:            list[str] = field(default_factory=list)
    diff:                str | None = None               # вывод "show | compare"
    error:               str | None = None
    reserve_check:       str | None = None               # итог пинга резерва перед переключением
    # True специально для случая «резерв сам недоступен» (в отличие от
    # прочих ошибок — не задан IP, переключение отключено и т.п.) —
    # вызывающий код (pipeline) отличает это как повод для эскалации.
    reserve_unavailable: bool = False
    reserve_description: str | None = None               # description резервного соседа (для провайдера)


class BgpPolicySwitcher:
    """Разбирает XML-конфиг (rpc get-config, ветка protocols/bgp) и строит
    план обмена политиками. Совместим и с lxml, и с xml.etree."""

    def __init__(self, config_xml) -> None:
        self.root = self._strip_ns(config_xml)

    def channels(
        self,
        priority_groups: tuple[str, ...] = (),
        only_groups:     tuple[str, ...] = (),
    ) -> list[BgpChannel]:
        """
        Список каналов связи по BGP-группам конфига: группа, IP соседа,
        описание, группы префиксов import/export и приоритет из суффикса
        -P<n> имён политик.

        only_groups — если задано, обрабатываются ТОЛЬКО перечисленные
        группы, остальные полностью игнорируются на уровне парсинга (см.
        const.PARSED_BGP_GROUPS) — временная мера против шума/ложных
        срабатываний от групп, которые пока не должны участвовать в
        диагностике. Пусто — без ограничения, обрабатываются все группы.

        priority_groups — группы в порядке убывания приоритета (напр.
        ("DC-MOSCOW",)): их каналы получают меньший group_rank и стоят
        выше в списке. Остальные группы — ниже, в порядке конфига.
        Внутри группы каналы отсортированы по приоритету P1..Pn
        (без приоритета — в конце группы).
        """
        result: list[BgpChannel] = []
        group_index: dict[str, int] = {}
        for grp in self.root.iter("group"):
            group_name = self._text(grp, "name")
            if not group_name:
                continue
            if only_groups and group_name not in only_groups:
                continue
            group_index.setdefault(group_name, len(group_index))
            if group_name in priority_groups:
                rank = priority_groups.index(group_name)
            else:
                rank = len(priority_groups) + group_index[group_name]
            for nb in grp.findall("neighbor"):
                imports = [self._el_text(e) for e in nb.findall("import")]
                exports = [self._el_text(e) for e in nb.findall("export")]
                result.append(BgpChannel(
                    group         = group_name,
                    neighbor      = self._text(nb, "name"),
                    description   = self._text(nb, "description") or None,
                    imports       = imports,
                    exports       = exports,
                    priority      = _policy_priority(imports, exports),
                    group_rank    = rank,
                    local_address = self._text(nb, "local-address") or None,
                ))
        # Сортировка стабильная: приоритетные группы выше, внутри группы — P1..Pn.
        result.sort(key=lambda c: (c.group_rank, c.priority is None, c.priority or 0))
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
