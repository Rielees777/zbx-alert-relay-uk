from __future__ import annotations

import logging
import re

from models import ChannelInfo, PyrusSite
from providers import is_aliased, normalize_provider

logger = logging.getLogger(__name__)

# Типы канала в имени триггера (а не провайдеры). "inet" — трафик через
# интернет по белым IP (без выделенного L2VPN и без конкретного оператора).
# "df" — тёмное волокно (dark fiber); в описании не обязательно последним
# сегментом, напр. "m1-df-ix-cortel": m1 — узел/ЦОД, df — тип (волокно),
# ix — транзитный ЦОД, через который идёт волокно (само по себе не тип и
# не провайдер, просто справочный сегмент), cortel — провайдер.
_CHANNEL_TYPES = frozenset({"l2vpn", "ipsec", "inet", "df"})

# Тип канала из триггера → услуга (колонка «Услуга» в Pyrus).
_TYPE_TO_SERVICE = {"inet": "интернет", "df": "тёмное волокно"}

# "RPM потери до m1-ttk-l2vpn - 100 %"  → узел m1, провайдер ttk, тип l2vpn
# "RPM потери до m1-inet - 100 %"       → узел m1, без провайдера, тип inet
_SPEC_RE = re.compile(r'до\s+(?P<spec>\S+)', re.IGNORECASE)
_LOSS_RE = re.compile(r'(\d+(?:[.,]\d+)?)\s*%')

# Site-триггер: "Потери до <видимое имя узла>", напр.
# "Потери до Санкт-Петербург, ул. Киевская д. 5, корп. 4".
# Префикс без "RPM" впереди отличает его от канального "RPM потери до <канал>".
_SITE_PREFIX = "потери до"
_CHANNEL_PREFIX = "rpm потери до"


class TriggerInfo:
    """Распарсенный триггер Zabbix: узел, (опц.) провайдер, тип канала.
    Либо site-триггер («Потери до <имя площадки>») — тогда is_site=True."""

    def __init__(self, raw: str) -> None:
        self.raw          = raw
        self.node:         str | None   = None
        self.provider_raw: str | None   = None
        self.provider:     str | None   = None   # нормализованный, напр. "ТТК"
        self.channel_type: str | None   = None   # l2vpn / inet / ipsec
        self.loss_pct:     float | None = None   # % потерь из имени триггера
        self.channel_spec: str | None   = None   # "m1-rtk-l2vpn" — как в ключах item'ов Zabbix
        self.is_site:      bool         = False  # триггер вида "Потери до <площадка>"
        self.site_name:    str | None   = None   # имя площадки (= видимое имя узла)

        raw_stripped = raw.strip()
        casefolded   = raw_stripped.casefold()
        if casefolded.startswith(_SITE_PREFIX) and not casefolded.startswith(_CHANNEL_PREFIX):
            self.is_site   = True
            tail           = raw_stripped[len(_SITE_PREFIX):].strip()
            self.site_name = self._strip_loss_suffix(tail)
        else:
            m = _SPEC_RE.search(raw)
            if m:
                self.channel_spec = m.group("spec")
                parts = [p for p in m.group("spec").split("-") if p]
                if parts:
                    self.node = parts[0]
                    rest = parts[1:]
                    # Тип канала — известный маркер СРЕДИ всех сегментов, не
                    # обязательно последним (напр. "m1-df-ix-cortel": df —
                    # тип, но не последний сегмент).
                    type_idx = next(
                        (i for i, seg in enumerate(rest) if seg.lower() in _CHANNEL_TYPES), None,
                    )
                    if type_idx is not None:
                        self.channel_type = rest[type_idx].lower()
                        rest = rest[:type_idx] + rest[type_idx + 1:]

                    if len(rest) == 1:
                        # Обычный случай: ровно один сегмент между узлом и
                        # типом — провайдер, даже если алиаса для него ещё
                        # нет (тогда normalize_provider вернёт как есть и
                        # залогирует предупреждение — как и раньше).
                        self.provider_raw = rest[0]
                        self.provider     = normalize_provider(rest[0])
                    elif len(rest) > 1:
                        # Несколько сегментов сразу (напр. "df-ix-cortel" за
                        # вычетом типа) — позиция провайдера не гарантирована
                        # (может быть справочный сегмент вроде транзитного
                        # ЦОД "ix"), поэтому ищем сегмент, который реально
                        # опознаётся как известный провайдер, а не берём по
                        # позиции наугад.
                        hint = provider_from_description("-".join(rest))
                        if hint:
                            self.provider     = hint
                            self.provider_raw = next(
                                (seg for seg in rest if is_aliased(seg)), rest[0],
                            )
                        else:
                            logger.warning(
                                "Триггер %r: несколько сегментов (%r) между узлом и типом, "
                                "провайдер не опознан ни в одном — договор может не найтись",
                                raw, rest,
                            )

        m_loss = _LOSS_RE.search(raw)
        if m_loss:
            self.loss_pct = float(m_loss.group(1).replace(",", "."))

    def __repr__(self) -> str:
        return (
            f"TriggerInfo(node={self.node!r}, "
            f"provider={self.provider!r}, "
            f"channel_type={self.channel_type!r})"
        )

    @staticmethod
    def _strip_loss_suffix(text: str) -> str:
        """Отрезает необязательный хвост "- NN %" от конца строки триггера
        (без регулярных выражений) — то, что осталось, это имя площадки."""
        text = text.strip()
        if not text.endswith("%"):
            return text
        idx = text.rfind("-")
        if idx == -1:
            return text
        number_part = text[idx + 1:-1].strip().replace(",", ".")
        integer_part, _, fractional_part = number_part.partition(".")
        if integer_part.isdigit() and (fractional_part == "" or fractional_part.isdigit()):
            return text[:idx].strip()
        return text

    @staticmethod
    def _normalize(text: str | None) -> str:
        """
        Сравнение имени площадки нечувствительно к пунктуации и пробелам:
        "ул. Киевская д. 5" и "ул.Киевская д.5" — один и тот же адрес, но
        в имени триггера и видимом имени узла оформлены по-разному.
        Оставляем только буквы/цифры в нижнем регистре.
        """
        return "".join(ch for ch in (text or "").casefold() if ch.isalnum())

    def matches_visible_name(self, host_name: str | None) -> bool:
        """
        Site-триггер ("Потери до <площадка>") обязан указывать то же имя,
        что и видимое имя узла Zabbix в том же алерте. Несовпадение
        означает, что триггер, вероятно, относится не к этому хосту —
        такой алерт обрабатывать нельзя.

        Для канальных триггеров сравнение не применяется (всегда True).
        """
        if not self.is_site:
            return True
        return self._normalize(self.site_name) == self._normalize(host_name)


_DESC_SPLIT_RE = re.compile(r'[^0-9a-zA-Zа-яА-ЯёЁ]+')


def provider_from_description(description: str | None) -> str | None:
    """
    Провайдер по описанию физического/логического интерфейса на устройстве
    (напр. "uk-spb-kievskaya5-obit-l2vpn uplink") — используется для
    site-алертов, где в имени триггера провайдера нет, но описание
    конкретного проблемного канала (см. pipeline._pick_worst_l2vpn_link)
    обычно его содержит.

    Описание бьётся на сегменты по любым не-буквенно-цифровым разделителям
    и каждый сегмент проверяется отдельно через is_aliased — так сегмент
    типа канала (l2vpn/uplink) или часть имени узла не даст ложного
    срабатывания на короткий алиас (напр. "rt"), как было бы при поиске
    подстроки по всему описанию сразу.
    """
    if not description:
        return None
    for segment in _DESC_SPLIT_RE.split(description):
        if segment and is_aliased(segment):
            return normalize_provider(segment)
    return None


def find_channel_by_trigger(
    trigger_name: str,
    site: PyrusSite,
    host_name: str | None = None,
    channel_hint: str | None = None,
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

    Для site-триггеров дополнительно требуется совпадение имени площадки
    из триггера с видимым именем узла того же алерта (`host_name`) —
    иначе канал не сопоставляется вовсе. Провайдера в site-триггере нет, но
    `channel_hint` (описание конкретного проблемного канала с устройства,
    см. pipeline._pick_worst_l2vpn_link) может его содержать — тогда канал
    выбирается по совпадению провайдера, а не первый попавшийся L2VPN.
    """
    trigger = TriggerInfo(trigger_name)
    logger.debug(
        "find_channel_by_trigger: trigger=%r → is_site=%s site_name=%r node=%r "
        "provider=%r channel_type=%r",
        trigger_name, trigger.is_site, trigger.site_name,
        trigger.node, trigger.provider, trigger.channel_type,
    )
    if not site.channels:
        logger.debug("find_channel_by_trigger: у задачи task:%d нет каналов", site.task_id)
        return None

    # Site-триггер («Потери до <площадка>»): провайдера в имени нет —
    # берём l2vpn-канал площадки (как и для канальных алертов, обрабатываем
    # только L2VPN).
    if trigger.is_site:
        if not trigger.matches_visible_name(host_name):
            logger.warning(
                "Площадка из триггера %r не совпадает с видимым именем узла %r — "
                "канал Pyrus не сопоставляется",
                trigger.site_name, host_name,
            )
            return None
        logger.debug("find_channel_by_trigger: площадка %r совпадает с узлом %r", trigger.site_name, host_name)
        typed = [ch for ch in site.channels
                 if ch.service and "l2vpn" in ch.service.lower()]

        # Если известно описание конкретного проблемного канала (пришло из
        # поканальной проверки на устройстве) — сначала пробуем выбрать
        # канал Pyrus по совпадению провайдера, а не первый L2VPN подряд.
        hint_provider = provider_from_description(channel_hint)
        if hint_provider:
            by_provider = [ch for ch in typed if normalize_provider(ch.provider) == hint_provider]
            if by_provider:
                logger.debug(
                    "find_channel_by_trigger: канал по описанию %r → провайдер %r → task:%d",
                    channel_hint, hint_provider, site.task_id,
                )
                return by_provider[0]
            logger.debug(
                "find_channel_by_trigger: провайдер %r из описания %r не найден среди l2vpn-каналов "
                "площадки (providers=%r) — фолбэк",
                hint_provider, channel_hint, [ch.provider for ch in typed],
            )

        if typed:
            return typed[0]
        logger.debug(
            "find_channel_by_trigger: у task:%d нет канала со службой l2vpn (services=%r), каналов=%d",
            site.task_id, [ch.service for ch in site.channels], len(site.channels),
        )
        return site.channels[0] if len(site.channels) == 1 else None

    matches = list(site.channels)

    # 1. Фильтр по провайдеру (у inet-триггера провайдера нет — пропускаем).
    if trigger.provider:
        matches = [
            ch for ch in matches
            if normalize_provider(ch.provider) == trigger.provider
        ]
        if not matches:
            logger.debug(
                "find_channel_by_trigger: нет канала с провайдером %r (providers=%r)",
                trigger.provider, [ch.provider for ch in site.channels],
            )
            return None

    # 2. Фильтр по услуге, соответствующей типу канала из триггера.
    if trigger.channel_type:
        want = _TYPE_TO_SERVICE.get(trigger.channel_type, trigger.channel_type)
        typed = [ch for ch in matches if ch.service and want in ch.service.lower()]
        if not typed:
            logger.debug(
                "find_channel_by_trigger: нет канала со службой %r среди %r (после фильтра провайдера)",
                want, [ch.service for ch in matches],
            )
        return typed[0] if typed else None

    # 3. Тип не распознан — только если канал однозначен.
    if len(matches) != 1:
        logger.debug(
            "find_channel_by_trigger: тип канала не распознан в триггере, каналов после фильтра=%d — неоднозначно",
            len(matches),
        )
    return matches[0] if len(matches) == 1 else None
