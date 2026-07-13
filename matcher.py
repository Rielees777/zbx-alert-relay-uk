from __future__ import annotations

import logging

from models import ChannelInfo, PyrusSite
from trigger_parser import find_channel_by_trigger

logger = logging.getLogger(__name__)


class RegistryMatcher:
    """
    Матчит Zabbix-хост с задачей Pyrus по IP-адресу роутера узла сети.

    Сопоставление выполняется единственным способом — по совпадению IP
    хоста Zabbix с полем "IP-адрес роутера узла сети" задачи Pyrus.
    """

    def __init__(self, sites: list[PyrusSite]) -> None:
        self._sites = sites
        self._by_ip: dict[str, PyrusSite] = {}   # router_ip → site
        self._build()

    def _build(self) -> None:
        for site in self._sites:
            if ip := site.ip_key:
                self._by_ip[ip] = site

        logger.info(
            "RegistryMatcher: %d задач | %d IP",
            len(self._sites), len(self._by_ip),
        )

    def find(self, ip: str | None) -> PyrusSite | None:
        ip_key = (ip or "").strip()
        if not ip_key:
            return None

        if site := self._by_ip.get(ip_key):
            logger.debug("Pyrus (ip): %r → task:%d", ip_key, site.task_id)
            return site

        logger.debug("Pyrus: нет совпадения для ip=%r", ip)
        return None

    def find_channel(
        self,
        site: PyrusSite,
        trigger_name: str,
        host_name: str | None = None,
        channel_hint: str | None = None,
    ) -> ChannelInfo | None:
        """
        Находит нужный канал Pyrus по полному имени триггера Zabbix.
        Нормализует провайдер из триггера и сравнивает с каналами задачи.
        Для site-триггеров `host_name` (видимое имя узла того же алерта)
        обязателен — без совпадения с именем площадки канал не отдаётся;
        `channel_hint` (описание конкретного проблемного канала с
        устройства) уточняет выбор среди нескольких L2VPN-каналов площадки.
        """
        logger.debug(
            "find_channel: task:%d, trigger=%r, host_name=%r, channel_hint=%r, каналов в задаче=%d",
            site.task_id, trigger_name, host_name, channel_hint, len(site.channels),
        )
        channel = find_channel_by_trigger(trigger_name, site, host_name, channel_hint)
        logger.debug(
            "find_channel: task:%d → %s",
            site.task_id,
            f"provider={channel.provider!r} contract={channel.contract!r} service={channel.service!r}"
            if channel else "канал не найден",
        )
        return channel
