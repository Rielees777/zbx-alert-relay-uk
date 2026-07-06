from dataclasses import dataclass


TRIGGER_PATTERNS: list[str] = [
    "RPM потери до",
]

# Обрабатываются только инциденты L2VPN-каналов. Всё остальное — inet,
# ipsec, нераспознанные/некорректные имена триггеров (channel_type=None) —
# игнорируется (не обрабатывается и не шлётся в чат).
ALLOWED_CHANNEL_TYPES: frozenset[str] = frozenset({"l2vpn"})

PING_COUNT: int = 100
L2VPN_LOSS_THRESHOLD_PCT: float = 5.0
CHANNEL_UTIL_THRESHOLD_PCT: float = 90.0
UTIL_LOOKBACK_MINUTES: int = 20
ACTIVE_MINUTES: int = 60

# Интервал расписания проверок и минимальный возраст алерта: реагируем
# только на триггеры, длящиеся дольше 5 минут; более молодые пропускаются
# и будут рассмотрены на следующем цикле расписания.
CHECK_INTERVAL_MINUTES: int = 5
MIN_ALERT_AGE_SEC: int = 300

JUNOS_WANT_L2VPN: str = "l2vpn"
JUNOS_WANT_IPSEC: str = "ipsec"

# Автопереключение каналов (JunosApi.switch_channel) временно отключено:
# логика пересматривается под приоритеты каналов (P1..Pn) по всем группам.
CHANNEL_SWITCHING_ENABLED: bool = False

# BGP-группы в порядке убывания приоритета: каналы этих групп стоят выше
# в инвентаризации (list_bgp_channels). Не перечисленные группы — ниже,
# в порядке следования в конфиге.
PRIORITY_BGP_GROUPS: tuple[str, ...] = ("DC-MOSCOW",)

# Email операторов связи для отправки обращений напрямую провайдеру.
# Ключ — канонический провайдер (как в providers.PROVIDER_ALIASES и в
# ChannelInfo.provider из Pyrus). Если провайдера здесь нет — письмо уходит
# на запасной адрес Settings.mail_to_default (если он задан).
PROVIDER_EMAILS: dict[str, str] = {
    # "Ростелеком": "noc@rt.ru",
    # "ТТК":        "support@ttk.ru",
    # "МТС":        "b2b@mts.ru",
}


def get_provider_email(provider: str | None) -> str | None:
    return PROVIDER_EMAILS.get(provider) if provider else None


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
