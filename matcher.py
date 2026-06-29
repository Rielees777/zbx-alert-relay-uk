from __future__ import annotations

import logging
import re

from rapidfuzz import fuzz, process

from const import MANUAL_MATCHES
from models import ChannelInfo, PyrusSite
from trigger_parser import find_channel_by_trigger

logger = logging.getLogger(__name__)

# Токены, которые по-разному пишутся в Zabbix и Pyrus — убираем при сравнении
_NOISE = frozenset({
    "г", "гор", "город",
    "обл", "область",
    "р-н", "район",
    "ул", "улица",
    "пр", "пр-т", "просп", "проспект",
    "пер", "переулок",
    "ш", "шоссе",
    "д", "дом",
    "к", "корп", "корпус",
    "стр", "строение",
    "б-р", "бул", "бульвар",
    "наб", "набережная",
    "пл", "площадь",
    "кв", "квартал",
    "тракт",
    "рф", "россия",
})

FUZZY_THRESHOLD = 80  # минимальный score для автоматического матчинга


def normalize(addr: str | None) -> str:
    if not addr:
        return ""
    s = addr.lower().replace("ё", "е")
    s = re.sub(r"[.,;/\\№#\"']", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    tokens = [t for t in s.split() if t not in _NOISE]
    return " ".join(tokens)


class RegistryMatcher:
    """
    Матчит Zabbix-хост (по visible_name) с задачей Pyrus.

    Порядок поиска:
      1. MANUAL_MATCHES — хардкод исключений из const.py
      2. zabbix_hostname — прямое совпадение по полю задачи Pyrus
      3. fuzzy — сравнение visible_name с адресом задачи Pyrus
    """

    def __init__(self, sites: list[PyrusSite]) -> None:
        self._sites = sites
        self._by_task_id:  dict[int, PyrusSite] = {}
        self._by_hostname: dict[str, PyrusSite] = {}   # zabbix_hostname.lower() → site
        self._addr_index:  dict[int, tuple[str, PyrusSite]] = {}  # task_id → (norm_addr, site)
        self._manual:      dict[str, PyrusSite] = {}   # host_name.lower() → site
        self._build()

    def _build(self) -> None:
        for site in self._sites:
            self._by_task_id[site.task_id] = site
            if key := site.match_key:
                self._by_hostname[key.lower()] = site
            if site.address:
                self._addr_index[site.task_id] = (normalize(site.address), site)

        for host_name, task_id in MANUAL_MATCHES.items():
            site = self._by_task_id.get(task_id)
            if site:
                self._manual[host_name.lower()] = site
            else:
                logger.warning("MANUAL_MATCHES: задача %d не найдена в реестре Pyrus", task_id)

        logger.info(
            "RegistryMatcher: %d задач | %d hostname | %d адресов | %d ручных",
            len(self._sites), len(self._by_hostname),
            len(self._addr_index), len(self._manual),
        )

    def find(self, host_name: str) -> PyrusSite | None:
        if not host_name:
            return None
        hn = host_name.lower()

        # 1. Ручной хардкод
        if site := self._manual.get(hn):
            logger.debug("Pyrus (manual): %r → task:%d", host_name, site.task_id)
            return site

        # 2. Прямое совпадение по zabbix_hostname
        if site := self._by_hostname.get(hn):
            logger.debug("Pyrus (hostname): %r → task:%d", host_name, site.task_id)
            return site

        # 3. Fuzzy по адресу
        query = normalize(host_name)
        if not query or not self._addr_index:
            return None

        choices = {tid: norm for tid, (norm, _) in self._addr_index.items()}
        results = process.extract(query, choices, scorer=fuzz.token_set_ratio, limit=1)
        if results:
            _addr, score, best_tid = results[0]
            if score >= FUZZY_THRESHOLD:
                site = self._addr_index[best_tid][1]
                logger.debug("Pyrus (fuzzy score=%d): %r → task:%d %s", score, host_name, site.task_id, site.address)
                return site

        logger.debug("Pyrus: нет совпадения для %r", host_name)
        return None

    def find_channel(self, site: PyrusSite, trigger_name: str) -> ChannelInfo | None:
        """
        Находит нужный канал Pyrus по полному имени триггера Zabbix.
        Нормализует провайдер из триггера и сравнивает с каналами задачи.
        """
        return find_channel_by_trigger(trigger_name, site)
