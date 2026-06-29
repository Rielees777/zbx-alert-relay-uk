from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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


class IncidentDecision(str, Enum):
    CHANNEL_DOWN     = "channel_down"
    HIGH_UTILIZATION = "high_utilization"
    DEGRADED_CHANNEL = "degraded_channel"
    IPSEC_LOSS       = "ipsec_loss"
    FALSE_POSITIVE   = "false_positive"
    ERROR            = "error"


@dataclass
class IncidentReport:
    problem:         RpmProblem
    ping_results:    list[PingResult]        = field(default_factory=list)
    ipsec_results:   list[PingResult]        = field(default_factory=list)
    utilization_pct: float | None            = None
    decision:        IncidentDecision | None = None
    error:           str | None              = None

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
