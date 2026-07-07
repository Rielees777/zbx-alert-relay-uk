"""
Минимальный клиент VK Teams / ICQ Bot API.

Проект использует бота только для отправки уведомлений
(messages/sendText) — polling-инфраструктура (dispatcher, handlers,
events) удалена за ненадобностью.
"""

import asyncio
import logging
from functools import cached_property
from typing import Optional

import aiohttp

LOG = logging.getLogger(__name__)


class Bot:
    def __init__(
        self,
        token: str,
        proxy_url: str,
        api_url_base: str = None,
        name: str = None,
        version: str = None,
        timeout_s: int = 30,
    ):
        self.token = token
        self.api_base_url = (
            "https://api.icq.net/bot/v1" if api_url_base is None else api_url_base
        )
        self.name = name
        self.version = version
        self.timeout_s = timeout_s
        self.proxy_url = proxy_url
        self._uin = token.split(":")[-1]

        self._session: Optional[aiohttp.ClientSession] = None

        LOG.info(
            f"Bot initialized: name={self.name}, version={self.version}, uin={self._uin}, "
            f"proxy={self.proxy_url}"
        )

    @cached_property
    def user_agent(self):
        library_version = "0.1.0"
        return "{name}/{version} (uin={uin}) bot-python-async/{library_version}".format(
            name=self.name if self.name is not None else "bot",
            version=self.version if self.version is not None else "base",
            uin=self._uin if self._uin is not None else "",
            library_version=library_version,
        )

    @property
    def uin(self):
        return self._uin

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            LOG.debug("Creating new aiohttp ClientSession")
            connector = aiohttp.TCPConnector(ssl=False, limit=10, limit_per_host=5)
            self._session = aiohttp.ClientSession(
                headers={"User-Agent": self.user_agent},
                timeout=aiohttp.ClientTimeout(total=self.timeout_s),
                connector=connector,
                proxy=self.proxy_url,
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            LOG.debug("Closing aiohttp session")
            await self._session.close()

    async def send_text(self, chat_id: str, text: str):
        max_retries = 3
        data = {
            "token": self.token,
            "chatId": chat_id,
            "text": text,
        }
        session = await self._get_session()
        for attempt in range(max_retries):
            try:
                async with session.post(
                    url=f"{self.api_base_url}/messages/sendText",
                    data=data,
                ) as response:
                    if response.status in (502, 503, 504) and attempt < max_retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return response
            except Exception as e:
                LOG.exception(f"Unexpected error in send_text: {e}")
