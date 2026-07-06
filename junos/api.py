from __future__ import annotations

import logging

from const import (
    CHANNEL_SWITCHING_ENABLED,
    JUNOS_WANT_IPSEC,
    JUNOS_WANT_L2VPN,
    PRIORITY_BGP_GROUPS,
)
from models import IncidentReport, L2vpnLink, PingResult, RpmProblem
from junos.parser import JunosInterfaceParser
from junos.pinger import JunosPinger
from junos.switcher import BgpChannel, BgpChannelParser, BgpPolicySwitcher, SwitchResult

logger = logging.getLogger(__name__)


class JunosApi:
    def __init__(self, settings) -> None:
        self._settings = settings

    def analyze_problem(self, problem: RpmProblem, count: int = 100) -> IncidentReport:
        if not problem.ip:
            return IncidentReport(
                problem=problem,
                error=f"Нет IP для хоста '{problem.host_name}'",
            )
        # Для site-алертов ("Потери до <площадка>") COD в имени триггера нет —
        # интерфейсные линки ищутся на устройстве без фильтра по COD.
        if not problem.cod_name and not problem.site_alert:
            return IncidentReport(
                problem=problem,
                error=f"Не удалось определить COD из триггера (host={problem.host_name})",
            )
        from jnpr.junos.exception import ConnectError
        try:
            with self._connect(problem.ip) as dev:
                # Транспорт L2VPN проверяется по ИНТЕРФЕЙСНЫМ адресам каналов
                # (серые /30 на L2). Адреса BGP-соседей — это IPSEC-туннели
                # поверх каналов, их проверяет analyze_ipsec.
                parser  = JunosInterfaceParser.from_device(dev)
                links   = parser.l2vpn_links(cod_name=problem.cod_name or "", want=JUNOS_WANT_L2VPN)
                pinger  = JunosPinger(dev)
                results = [pinger.ping_link(link, count=count) for link in links]
        except ConnectError as exc:
            # Железка недоступна по управлению — трактуем как полный обрыв канала.
            return IncidentReport(
                problem=problem,
                error=f"Устройство {problem.ip} недоступно по управлению: {exc}",
                unreachable=True,
            )
        except Exception as exc:
            return IncidentReport(
                problem=problem,
                error=f"Ошибка обработки {problem.ip}: {exc}",
            )
        return IncidentReport(problem=problem, ping_results=results)

    def analyze_ipsec(self, problem: RpmProblem, count: int = 100) -> list[PingResult]:
        """
        Проверка IPSEC-туннелей. Адреса BGP-соседей — это и есть адреса
        туннелей, построенных поверх каналов (description соседа называет
        транспортный канал: "m1-rtk-l2vpn"), поэтому цели пинга берутся из
        BGP-конфига; фолбэк — прежний поиск ipsec-интерфейсов по description.
        """
        if not problem.ip or (not problem.cod_name and not problem.site_alert):
            return []
        try:
            with self._connect(problem.ip) as dev:
                links = self._bgp_ping_targets(dev, problem)
                if not links:
                    logger.debug(
                        "BGP-соседи для IPSEC не найдены (host=%s) — фолбэк на интерфейсы",
                        problem.host_name,
                    )
                    parser = JunosInterfaceParser.from_device(dev)
                    links  = parser.l2vpn_links(cod_name=problem.cod_name or "", want=JUNOS_WANT_IPSEC)
                pinger = JunosPinger(dev)
                return [pinger.ping_link(link, count=count) for link in links]
        except Exception as exc:
            logger.warning(
                "Ошибка ping IPSEC %s (host=%s): %s",
                problem.ip, problem.host_name, exc,
            )
            return []

    @staticmethod
    def _read_bgp_config(dev):
        """XML-конфиг ветки protocols/bgp с открытого устройства."""
        from lxml import etree
        bgp_filter = etree.XML("<configuration><protocols><bgp/></protocols></configuration>")
        return dev.rpc.get_config(filter_xml=bgp_filter)

    def _bgp_ping_targets(self, dev, problem: RpmProblem) -> list[L2vpnLink]:
        """
        Цели пинга IPSEC-туннелей из BGP-конфига устройства: адрес
        BGP-соседа = адрес туннеля, а description соседа называет
        транспортный канал, через который туннель построен:
          • канальный алерт — туннель через канал из триггера
            (description == channel_spec, напр. "m1-rtk-l2vpn");
          • site-алерт — все туннели через l2vpn-каналы площадки.
        Пингуется IP соседа; source — local-address соседа, если задан.
        Пустой список — вызывающий код уходит в интерфейсный фолбэк.
        """
        try:
            channels = BgpChannelParser(self._read_bgp_config(dev)).channels()
        except Exception as exc:
            logger.warning("Не удалось прочитать BGP-конфиг %s: %s", problem.ip, exc)
            return []

        if problem.site_alert:
            targets = [c for c in channels if c.channel_type == "l2vpn"]
        elif problem.channel_spec:
            spec = problem.channel_spec.lower()
            targets = [c for c in channels if (c.description or "").lower() == spec]
        else:
            targets = []

        return [
            L2vpnLink(
                interface   = f"bgp:{c.group}",
                description = c.description or "",
                local_ip    = c.local_address or "",
                remote_ip   = c.neighbor,
            )
            for c in targets
        ]

    def list_bgp_channels(self, host_ip: str) -> list[BgpChannel]:
        """
        Инвентаризация каналов связи устройства: все BGP-группы и их соседи
        с описанием, группами префиксов import/export и приоритетом из
        суффикса -P<n> имён политик (1 — основной, 2 — резервный, …).

        Список отсортирован: сначала каналы приоритетных групп
        (const.PRIORITY_BGP_GROUPS, напр. DC-MOSCOW), затем остальные;
        внутри группы — по P1..Pn.
        """
        with self._connect(host_ip) as dev:
            cfg_xml = self._read_bgp_config(dev)

        channels = BgpChannelParser(cfg_xml).channels(priority_groups=PRIORITY_BGP_GROUPS)
        logger.info(
            "BGP-каналы %s: %d шт. (%s)",
            host_ip, len(channels),
            ", ".join(f"{c.group}/{c.description or c.neighbor}:P{c.priority or '?'}" for c in channels),
        )
        return channels

    def switch_channel(
        self,
        problem:         RpmProblem,
        group:           str = "ebgp",
        dry_run:         bool = False,
        confirm_minutes: int | None = 5,
    ) -> SwitchResult:
        """
        Переключает канал основной↔резервный: меняет местами пары BGP-политик
        import/export между двумя соседями группы (P1 ↔ P2). Операция
        симметрична — повторный вызов возвращает исходное состояние.

        ВРЕМЕННО ОТКЛЮЧЕНО (const.CHANNEL_SWITCHING_ENABLED = False):
        логика пересматривается под приоритеты каналов по всем группам —
        см. list_bgp_channels.

        dry_run=True — построить план, загрузить кандидат-конфиг, снять diff
        и откатить БЕЗ commit (безопасная проверка на живом устройстве).

        confirm_minutes — использовать `commit confirmed N`: если процесс
        после переключения потеряет доступ к железке и не подтвердит commit,
        устройство само откатится через N минут. None — обычный commit.
        """
        result = SwitchResult(success=False, dry_run=dry_run, group=group)
        if not CHANNEL_SWITCHING_ENABLED:
            result.error = (
                "Переключение каналов временно отключено "
                "(const.CHANNEL_SWITCHING_ENABLED = False)"
            )
            logger.warning("switch_channel: %s (host=%s)", result.error, problem.host_name)
            return result
        if not problem.ip:
            result.error = f"Нет IP для хоста '{problem.host_name}'"
            return result

        try:
            from jnpr.junos.utils.config import Config

            with self._connect(problem.ip) as dev:
                cfg_xml = self._read_bgp_config(dev)

                plan = BgpPolicySwitcher(cfg_xml).plan_swap(
                    group=group, channel_spec=problem.channel_spec,
                )
                result.neighbors = (plan.a.address, plan.b.address)
                result.commands  = plan.commands()

                with Config(dev, mode="exclusive") as cu:
                    cu.load("\n".join(result.commands), format="set")
                    result.diff = cu.diff()
                    if dry_run:
                        cu.rollback()
                        result.success = True
                        logger.info(
                            "switch_channel DRY-RUN %s (group=%s): %s ↔ %s\n%s",
                            problem.ip, group, plan.a.address, plan.b.address, result.diff,
                        )
                        return result
                    if confirm_minutes:
                        cu.commit(
                            comment=f"auto channel switch: {problem.trigger_name}",
                            confirm=confirm_minutes,
                        )
                        # Подтверждаем сразу: доступ к железке не потерян.
                        cu.commit(comment="auto channel switch: confirm")
                    else:
                        cu.commit(comment=f"auto channel switch: {problem.trigger_name}")

            result.success = True
            logger.warning(
                "Канал переключён (%s ↔ %s) на %s, group=%s, trigger=%s",
                plan.a.address, plan.b.address, problem.ip, group, problem.trigger_name,
            )
        except Exception as exc:
            result.error = str(exc)
            logger.error("Ошибка переключения канала на %s: %s", problem.ip, exc)
        return result

    def _connect(self, host: str):
        from jnpr.junos import Device
        return Device(**self._settings.junos_kwargs(host))
