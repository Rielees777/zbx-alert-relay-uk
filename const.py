from dataclasses import dataclass


TRIGGER_PATTERNS: list[str] = [
    "RPM потери до",
]

PING_COUNT: int = 100
L2VPN_LOSS_THRESHOLD_PCT: float = 5.0
CHANNEL_UTIL_THRESHOLD_PCT: float = 90.0
UTIL_LOOKBACK_MINUTES: int = 20
ACTIVE_MINUTES: int = 60
MIN_ALERT_AGE_SEC: int = 10

JUNOS_WANT_L2VPN: str = "l2vpn"
JUNOS_WANT_IPSEC: str = "ipsec"


@dataclass(frozen=True)
class COD:
    ip:       str
    name:     str = ""
    operator: str = ""
    contract: str = ""


@dataclass(frozen=True)
class CODs:
    o2:  COD = COD("10.70.145.2",   "o2",  operator="", contract="")
    ix:  COD = COD("10.70.145.101", "ix",  operator="", contract="")
    n11: COD = COD("10.70.138.51",  "n11", operator="", contract="")
    m1:  COD = COD("10.70.138.50",  "m1",  operator="", contract="")


def get_cod_by_name(name: str | None) -> COD | None:
    if not name:
        return None
    cods = CODs()
    for cod in (cods.o2, cods.ix, cods.n11, cods.m1):
        if cod.name == name:
            return cod
    return None
