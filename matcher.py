from __future__ import annotations

import logging

from const import MANUAL_MATCHES
from models import ChannelInfo, PyrusSite
from trigger_parser import find_channel_by_trigger

logger = logging.getLogger(__name__)


class RegistryMatcher:
    """
    Матчит Zabbix-хост с задачей Pyrus.

    Порядок поиска:
      1. MANUAL_MATCHES — хардкод исключений из const.py
      2. zabbix_hostname — прямое совпадение по полю задачи Pyrus
      3. IP-адрес — совпадение IP хоста Zabbix с полем
         "IP-адрес роутера узла сети" задачи Pyrus
    """

    def __init__(self, sites: list[PyrusSite]) -> None:
        self._sites = sites
        self._by_task_id:  dict[int, PyrusSite] = {}
        self._by_hostname: dict[str, PyrusSite] = {}   # zabbix_hostname.lower() → site
        self._by_ip:       dict[str, PyrusSite] = {}    # router_ip → site
        self._manual:      dict[str, PyrusSite] = {}   # host_name.lower() → site
        self._build()

    def _build(self) -> None:
        for site in self._sites:
            self._by_task_id[site.task_id] = site
            if key := site.match_key:
                self._by_hostname[key.lower()] = site
            if ip := site.ip_key:
                self._by_ip[ip] = site

        for host_name, task_id in MANUAL_MATCHES.items():
            site = self._by_task_id.get(task_id)
            if site:
                self._manual[host_name.lower()] = site
            else:
                logger.warning("MANUAL_MATCHES: задача %d не найдена в реестре Pyrus", task_id)

        logger.info(
            "RegistryMatcher: %d задач | %d hostname | %d IP | %d ручных",
            len(self._sites), len(self._by_hostname),
            len(self._by_ip), len(self._manual),
        )

    def find(self, host_name: str, ip: str | None = None) -> PyrusSite | None:
        if not host_name and not ip:
            return None
        hn = (host_name or "").lower()

        # 1. Ручной хардкод
        if hn and (site := self._manual.get(hn)):
            logger.debug("Pyrus (manual): %r → task:%d", host_name, site.task_id)
            return site

        # 2. Прямое совпадение по zabbix_hostname
        if hn and (site := self._by_hostname.get(hn)):
            logger.debug("Pyrus (hostname): %r → task:%d", host_name, site.task_id)
            return site

        # 3. Совпадение по IP-адресу роутера узла сети
        ip_key = (ip or "").strip()
        if ip_key and (site := self._by_ip.get(ip_key)):
            logger.debug("Pyrus (ip): %r → task:%d %s", ip_key, site.task_id, site.router_ip)
            return site

        logger.debug("Pyrus: нет совпадения для host=%r ip=%r", host_name, ip)
        return None

    def find_channel(self, site: PyrusSite, trigger_name: str) -> ChannelInfo | None:
        """
        Находит нужный канал Pyrus по полному имени триггера Zabbix.
        Нормализует провайдер из триггера и сравнивает с каналами задачи.
        """
        return find_channel_by_trigger(trigger_name, site)
