from __future__ import annotations

import logging

from const import (
    CHANNEL_SWITCHING_ENABLED,
    JUNOS_WANT_DARK_FIBER,
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
        from jnpr.junos.exception import ConnectError, RpcTimeoutError
        try:
            with self._connect(problem.ip) as dev:
                # Транспорт L2VPN проверяется по ИНТЕРФЕЙСНЫМ адресам каналов
                # (серые /30 на L2). Адреса BGP-соседей — это IPSEC-туннели
                # поверх каналов, их проверяет analyze_ipsec.
                parser = JunosInterfaceParser.from_device(dev)
                if problem.site_alert:
                    # Site-алерт не называет канал явно — по регламенту в
                    # этом случае всегда проверяется ОСНОВНОЙ канал площадки
                    # (P1 по приоритету BGP), а не перебор всех l2vpn-
                    # интерфейсов подряд.
                    links = self._primary_l2vpn_link(dev, parser)
                else:
                    links = parser.l2vpn_links(cod_name=problem.cod_name or "", want=JUNOS_WANT_L2VPN)
                pinger  = JunosPinger(dev)
                results = [pinger.ping_link(link, count=count) for link in links]
        except (ConnectError, RpcTimeoutError) as exc:
            # Железка недоступна по управлению (ConnectError), либо
            # подключились, но устройство не ответило на RPC-запрос
            # диагностики за отведённое время (RpcTimeoutError — напр.
            # get-interface-information). Оба случая трактуем как полный
            # обрыв канала, а не тихую ERROR: RpcTimeoutError — это прямой
            # сигнал "устройство не отвечает", а не ошибка обработки (та же
            # логика уже применяется в JunosPinger.ping_loss для RPC ping;
            # раньше она не распространялась на остальные RPC-запросы, и
            # такие инциденты уходили в ERROR без единого уведомления).
            return IncidentReport(
                problem=problem,
                error=f"Устройство {problem.ip} не отвечает: {exc}",
                unreachable=True,
            )
        except Exception as exc:
            return IncidentReport(
                problem=problem,
                error=f"Ошибка обработки {problem.ip}: {exc}",
            )
        return IncidentReport(problem=problem, ping_results=results)

    def analyze_ipsec(self, problem: RpmProblem, count: int = 100) -> list[PingResult] | None:
        """
        Проверка IPSEC-туннелей. Адреса BGP-соседей — это и есть адреса
        туннелей, построенных поверх каналов (description соседа называет
        транспортный канал: "m1-rtk-l2vpn"), поэтому цели пинга берутся из
        BGP-конфига; фолбэк — прежний поиск ipsec-интерфейсов по description.

        Возвращает None, если проверку выполнить не удалось (обрыв
        подключения, ошибка RPC и т.п.) — отличаем от штатного «проверили,
        потерь нет». Раз L2VPN-транспорт уже подтверждён исправным
        (analyze_ipsec вызывается только тогда), а QoS в сети не настроен,
        не пропинговать IPSEC с высокой вероятностью означает, что канал
        всё-таки лёг — вызывающий код (pipeline._handle_l2vpn_ok) трактует
        None так же, как потери, а не как ложное срабатывание.
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
                "Ошибка ping IPSEC %s (host=%s): %s — трактуем как потери в тоннеле",
                problem.ip, problem.host_name, exc,
            )
            return None

    def _primary_l2vpn_link(self, dev, parser: JunosInterfaceParser) -> list[L2vpnLink]:
        """
        Основной канал площадки для site-алерта: P1 среди l2vpn-каналов по
        приоритету BGP (та же сортировка, что list_bgp_channels —
        const.PRIORITY_BGP_GROUPS, внутри группы P1..Pn). Найденное
        описание канала сопоставляется с l2vpn-интерфейсом устройства —
        пинг идёт по ИНТЕРФЕЙСНОМУ адресу (L2-транспорт), а не по адресу
        BGP-соседа (это IPSEC-туннель, см. _bgp_ping_targets).

        Основным каналом может быть и тёмное волокно (description вида
        "m1-df-ix-cortel" — df, не l2vpn), поэтому кандидатами считаются
        оба типа: l2vpn И df.

        Если BGP-конфиг не читается, подходящих каналов в нём нет, либо
        описание P1-канала не находится среди интерфейсов устройства —
        фолбэк на прежнее поведение (все l2vpn/df-интерфейсы без фильтра
        по конкретному каналу).
        """
        try:
            channels = BgpChannelParser(self._read_bgp_config(dev)).channels(
                priority_groups=PRIORITY_BGP_GROUPS,
            )
        except Exception as exc:
            logger.warning("Не удалось прочитать BGP-конфиг для определения P1-канала: %s", exc)
            channels = []

        primary_channels = [c for c in channels if c.channel_type in (JUNOS_WANT_L2VPN, JUNOS_WANT_DARK_FIBER)]
        all_links = parser.l2vpn_links(cod_name="", want=JUNOS_WANT_L2VPN)
        all_links += [
            l for l in parser.l2vpn_links(cod_name="", want=JUNOS_WANT_DARK_FIBER)
            if l not in all_links
        ]
        if not primary_channels:
            logger.warning("В BGP-конфиге нет L2VPN/df-каналов — фолбэк на все l2vpn/df-интерфейсы устройства")
            return all_links

        primary = primary_channels[0]   # уже отсортированы по приоритету — P1 первый
        primary_desc = (primary.description or "").strip().lower()
        matched = [l for l in all_links if (l.description or "").strip().lower() == primary_desc]
        if matched:
            return matched

        logger.warning(
            "Основной канал (P1, %r) не нашёлся среди l2vpn/df-интерфейсов устройства — фолбэк на все",
            primary.description,
        )
        return all_links

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
          • site-алерт — туннель через ОСНОВНОЙ (P1 по приоритету) канал
            площадки (l2vpn или df), тот же, что уже проверен в
            analyze_problem — не все каналы сразу.
        Пингуется IP соседа; source — local-address соседа, если задан.
        Пустой список — вызывающий код уходит в интерфейсный фолбэк.
        """
        try:
            channels = BgpChannelParser(self._read_bgp_config(dev)).channels(
                priority_groups=PRIORITY_BGP_GROUPS,
            )
        except Exception as exc:
            logger.warning("Не удалось прочитать BGP-конфиг %s: %s", problem.ip, exc)
            return []

        if problem.site_alert:
            primary_channels = [c for c in channels if c.channel_type in (JUNOS_WANT_L2VPN, JUNOS_WANT_DARK_FIBER)]
            targets = primary_channels[:1]   # уже отсортированы по приоритету — только P1
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
        ping_count:      int = 20,
    ) -> SwitchResult:
        """
        Переключает канал основной↔резервный: меняет местами пары BGP-политик
        import/export между двумя соседями группы (P1 ↔ P2). Операция
        симметрична — повторный вызов возвращает исходное состояние.

        Только для site-алертов (problem.site_alert) — для канального
        алерта переключение отдельного канала не выполняется вовсе, там
        канал уже назван в триггере и обрабатывается через провайдера
        напрямую.

        ВРЕМЕННО ОТКЛЮЧЕНО (const.CHANNEL_SWITCHING_ENABLED = False):
        логика пересматривается под приоритеты каналов по всем группам —
        см. list_bgp_channels.

        Перед переключением резервный сосед (тот, что НЕ совпадает с
        channel_spec из триггера — на него и планируется переключение)
        пингуется (см. _check_reserve); если он сам недоступен или проверку
        выполнить не удалось — переключение отменяется БЕЗ обращения к
        конфигурации устройства (result.reserve_unavailable=True): менять
        шило на мыло (переключать на тоже нерабочий резерв) хуже, чем
        оставить как есть. Вызывающий код (pipeline._attempt_channel_switch)
        в этом случае формирует эскалацию — сообщение мониторингу и письмо
        провайдеру резервного канала.

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
        if not problem.site_alert:
            result.error = (
                "Переключение канала выполняется только для site-алертов "
                "(канальный алерт уже называет конкретный канал в триггере)"
            )
            logger.error("switch_channel: %s (host=%s)", result.error, problem.host_name)
            return result
        if not problem.ip:
            result.error = f"Нет IP для хоста '{problem.host_name}'"
            return result
        if not problem.channel_spec:
            result.error = "channel_spec не задан — невозможно определить, какой сосед резервный"
            logger.error("switch_channel: %s (host=%s)", result.error, problem.host_name)
            return result

        try:
            from jnpr.junos.utils.config import Config

            with self._connect(problem.ip) as dev:
                cfg_xml = self._read_bgp_config(dev)

                plan = BgpPolicySwitcher(cfg_xml).plan_swap(
                    group=group, channel_spec=problem.channel_spec,
                )
                result.neighbors = (plan.a.address, plan.b.address)

                reserve = (
                    plan.b if problem.channel_spec.lower() in (plan.a.description or "").lower()
                    else plan.a
                )
                result.reserve_description = reserve.description
                reserve_ok, result.reserve_check = self._check_reserve(dev, cfg_xml, reserve, ping_count)
                logger.info("switch_channel: проверка резерва %s (%s): %s",
                            reserve.address, reserve.description, result.reserve_check)
                if not reserve_ok:
                    result.reserve_unavailable = True
                    result.error = (
                        f"Резервный канал {reserve.address} ({reserve.description or '—'}) "
                        f"недоступен ({result.reserve_check}) — переключение отменено."
                    )
                    logger.error("switch_channel: %s (host=%s)", result.error, problem.host_name)
                    return result

                result.commands = plan.commands()

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

    @staticmethod
    def _check_reserve(dev, cfg_xml, reserve, count: int) -> tuple[bool, str]:
        """
        Пингует резервного BGP-соседа (адрес — сам туннель поверх канала,
        как и в _bgp_ping_targets) перед переключением на него; source —
        local-address того же канала в конфиге, если задан.

        Возвращает (доступен ли резерв, текстовое описание для лога/отчёта).
        RpcError при пинге (обрыв RPC и т.п.) трактуется так же, как полная
        недоступность — раз резерв не удалось проверить, переключать на
        него нельзя.
        """
        channels  = BgpChannelParser(cfg_xml).channels()
        ch        = next((c for c in channels if c.neighbor == reserve.address), None)
        source_ip = ch.local_address if ch else None
        try:
            loss = JunosPinger(dev).ping_loss(dest_ip=reserve.address, source_ip=source_ip, count=count)
        except RuntimeError as exc:
            return False, f"проверить не удалось: {exc}"
        if loss is None:
            return False, "потери не определены (нет ответа от устройства)"
        if loss >= count:
            return False, f"потери {loss}/{count} (не отвечает)"
        return True, f"потери {loss}/{count}"

    def _connect(self, host: str):
        from jnpr.junos import Device
        return Device(**self._settings.junos_kwargs(host))
