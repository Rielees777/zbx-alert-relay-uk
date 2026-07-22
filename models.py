from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field as PydanticField

SEVERITY_LABELS: dict[int, str] = {
    0: "Не классиф.",
    1: "Информация",
    2: "Предупреждение",
    3: "Средняя",
    4: "Высокая",
    5: "Чрезвычайная",
}


@dataclass
class ZabbixConfig:
    url:        str
    user:       str   = ""
    password:   str   = ""
    api_token:  str   = ""
    ssl_verify: bool  = True
    timeout:    float = 30.0

    @property
    def use_token(self) -> bool:
        return bool(self.api_token)




@dataclass
class RpmProblem:
    eventid:      str
    host_name:    str
    host_tech:    str
    ip:           str
    cod_name:     str | None
    cod_ip:       str | None
    provider:     str | None
    severity:     int
    started:      int
    resolved:     int
    trigger_name: str = ""
    channel_type: str | None = None         # тип канала из триггера: l2vpn / inet / ipsec
    trigger_loss_pct: float | None = None   # % потерь из имени триггера
    hostid:       str = ""                  # hostid Zabbix (для запроса item'ов утилизации)
    channel_spec: str | None = None         # "m1-rtk-l2vpn" — как в ключах item'ов isp.*
    site_alert:   bool = False              # триггер "Потери до <имя площадки>"

    @property
    def is_active(self) -> bool:
        return self.resolved == 0

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, str(self.severity))


@dataclass
class L2vpnLink:
    interface:   str
    description: str
    local_ip:    str
    remote_ip:   str


@dataclass
class PingResult:
    interface:   str
    description: str
    local_ip:    str
    remote_ip:   str
    loss:        int | None

    @property
    def has_loss(self) -> bool:
        return self.loss is not None and self.loss > 0


class ChannelInfo(BaseModel):
    """Одна строка таблицы каналов связи из реестра Pyrus"""
    provider:   str | None = None   # название провайдера
    channel_id: str | None = None
    bandwidth:  int | None = None   # Кбит/с
    contract:   str | None = None   # номер договора
    ip_address: str | None = None
    service:    str | None = None   # услуга: Интернет / L2VPN / Тёмное волокно / P2P (cell 49)
    email:      str | None = None   # email техподдержки провайдера (cell 52)
    # Адрес ЦОДа (гео), cell 48 — нужен, чтобы различать два канала ОДНОГО
    # провайдера, идущие в РАЗНЫЕ ЦОДы (по имени провайдера они неотличимы).
    # Сверяется с COD.alias (const.py) — сама сверка ещё не подключена, это
    # только парсинг и хранение значения.
    cod_address: str | None = None


class PyrusSite(BaseModel):
    """Одна задача реестра каналов связи из Pyrus"""
    task_id:          int
    directorate:      str | None = None
    zabbix_hostname:  str | None = None   # прямой ключ матчинга
    router_ip:        str | None = None   # IP-адрес роутера узла сети
    address:          str | None = None
    address_source:   str | None = None
    city:             str | None = None
    channels: list[ChannelInfo] = PydanticField(default_factory=list)

    @property
    def is_uk(self) -> bool:
        return bool(self.directorate and self.directorate.startswith("УК-"))

    @property
    def match_key(self) -> str | None:
        h = (self.zabbix_hostname or "").strip()
        return h if h and h != "-" else None

    @property
    def ip_key(self) -> str | None:
        ip = (self.router_ip or "").strip()
        return ip if ip and ip != "-" else None


class IncidentDecision(str, Enum):
    CHANNEL_DOWN     = "channel_down"
    HIGH_UTILIZATION = "high_utilization"
    DEGRADED_CHANNEL = "degraded_channel"
    IPSEC_LOSS       = "ipsec_loss"
    FALSE_POSITIVE   = "false_positive"
    ERROR            = "error"
    # Site-алерт: основной канал недоступен/деградировал, попытка
    # переключения на резерв не удалась, т.к. резерв сам недоступен —
    # эскалация (см. pipeline._attempt_channel_switch).
    RESERVE_UNAVAILABLE = "reserve_unavailable"


@dataclass
class IncidentReport:
    problem:         RpmProblem
    ping_results:    list[PingResult]        = field(default_factory=list)
    ipsec_results:   list[PingResult]        = field(default_factory=list)
    utilization_pct: float | None            = None
    decision:        IncidentDecision | None = None
    error:           str | None              = None
    unreachable:     bool                     = False   # железка недоступна по управлению (SSH)
    pyrus_site:      PyrusSite | None         = None
    pyrus_channel:   ChannelInfo | None       = None
    # Инвентарь BGP-каналов узла (junos.switcher.BgpChannel) — заполняется
    # только при DEGRADED_CHANNEL, для статистики по переключению (см.
    # pipeline._attach_bgp_channels); не типизирован явно, чтобы не тянуть
    # сюда junos и не заводить цикл импортов (junos → models).
    bgp_channels:    list                     = field(default_factory=list)
    # Site-алерт покрывает сразу все L2VPN-каналы площадки — degraded_link
    # это тот из ping_results, что определён как реально проблемный (см.
    # pipeline._pick_worst_l2vpn_link); используется для выбора канала
    # Pyrus и утилизации именно по нему, а не по площадке в среднем.
    # Для канальных алертов не заполняется (там канал уже задан триггером).
    degraded_link:   PingResult | None        = None
    # Эскалация RESERVE_UNAVAILABLE: pyrus_channel здесь — РЕЗЕРВНЫЙ канал
    # (для письма его провайдеру), primary_channel — основной, из-за
    # которого изначально сработал алерт (для сообщения мониторингу, где
    # нужно назвать оба). Для остальных decision не заполняется.
    primary_channel: ChannelInfo | None       = None

    @property
    def has_loss(self) -> bool:
        return any(r.has_loss for r in self.ping_results)

    @property
    def should_close(self) -> bool:
        if self.decision is not None:
            return self.decision == IncidentDecision.FALSE_POSITIVE
        return self.error is None and not self.has_loss

    @property
    def checked(self) -> bool:
        return self.error is None
