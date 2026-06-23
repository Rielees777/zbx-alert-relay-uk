import aiohttp
import asyncio
import logging
import ssl
import json
from typing import Optional, Any
from functools import cached_property

from .dispatcher import Dispatcher, StopDispatching
from .event import Event, EventType
from .handler import MessageHandler, Filter
from .types_bot import InlineKeyboardMarkup, Format
from .constant import ParseMode
from expiringdict import ExpiringDict

LOG = logging.getLogger(__name__)


class SkipDuplicateMessageHandler(MessageHandler):
    def __init__(self, cache):
        super(SkipDuplicateMessageHandler, self).__init__(filters=Filter.message)
        self.cache = cache

    def check(self, event, dispatcher):
        if super(SkipDuplicateMessageHandler, self).check(event=event, dispatcher=dispatcher):
            if self.cache.get(event.data["msgId"]) == event.data["text"]:
                raise StopDispatching
            return True
        return False


class InvalidToken(Exception):
    pass


def keyboard_to_json(keyboard_markup):
    if isinstance(keyboard_markup, InlineKeyboardMarkup):
        return keyboard_markup.to_json()
    elif isinstance(keyboard_markup, list):
        return json.dumps(keyboard_markup)
    else:
        return keyboard_markup


def format_to_json(format_):
    if isinstance(format_, Format):
        return format_.to_json()
    elif isinstance(format_, list):
        return json.dumps(format_)
    else:
        return format_


class Bot:
    def __init__(
        self,
        token: str,
        proxy_url: str,
        api_url_base: str = None,
        name: str = None,
        version: str = None,
        timeout_s: int = 30,
        poll_time_s: int = 90,
    ):
        self.token = token
        self.api_base_url = (
            "https://api.icq.net/bot/v1" if api_url_base is None else api_url_base
        )
        self.name = name
        self.version = version
        self.timeout_s = timeout_s
        self.poll_time_s = poll_time_s
        self.last_event_id = 0
        self.proxy_url = proxy_url

        self.dispatcher = Dispatcher(self)
        self.running = False
        self._uin = token.split(":")[-1]

        self._session: Optional[aiohttp.ClientSession] = None
        self._polling_task: Optional[asyncio.Task] = None
        self.__sent_im_cache = ExpiringDict(max_len=2**10, max_age_seconds=60)

        self.dispatcher.add_handler(SkipDuplicateMessageHandler(self.__sent_im_cache))

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

    async def __aenter__(self):
        await self.start_polling()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    async def idle(self):
        if self._polling_task:
            try:
                await self._polling_task
            except asyncio.CancelledError:
                LOG.debug("Polling task was cancelled")
        else:
            LOG.warning("No polling task is running. Call start_polling() first.")

    async def _start_polling(self):
        LOG.debug("Polling loop started")
        while self.running:
            try:
                response = await self.events_get()
                if response is None:
                    LOG.debug("Polling timeout (normal for long polling)")
                    continue
                if response.status == 200:
                    data = await response.json()
                    if "description" in data and data["description"] == "Invalid token":
                        LOG.error(f"Invalid token error: {data}")
                        raise InvalidToken(data)
                    if "events" in data:
                        for event in data["events"]:
                            await self.dispatcher.dispatch(
                                Event(
                                    type_=EventType(event["type"]),
                                    data=event["payload"],
                                )
                            )
                else:
                    LOG.warning(f"Unexpected response status: {response.status}")
            except InvalidToken as e:
                LOG.error(f"InvalidToken error: {e}")
                await asyncio.sleep(5)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                LOG.error(f"Proxy/connection error: {e}")
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                LOG.error(f"Exception while polling: {e}")
                await asyncio.sleep(1)

    async def start_polling(self):
        if not self.running:
            self.running = True
            self._polling_task = asyncio.create_task(self._start_polling())

    async def stop(self):
        if self.running:
            LOG.info("Stopping bot")
            self.running = False
            if self._polling_task:
                self._polling_task.cancel()
                try:
                    await self._polling_task
                except asyncio.CancelledError:
                    pass
            await self.close()

    async def events_get(self, poll_time_s: int = None, last_event_id: int = None):
        max_retries = 3
        poll_time_s = self.poll_time_s if poll_time_s is None else poll_time_s
        last_event_id = self.last_event_id if last_event_id is None else last_event_id

        session = await self._get_session()
        for attempt in range(max_retries):
            try:
                async with session.post(
                    url=f"{self.api_base_url}/events/get",
                    params={
                        "token": self.token,
                        "pollTime": poll_time_s,
                        "lastEventId": last_event_id,
                    },
                    timeout=aiohttp.ClientTimeout(total=poll_time_s + self.timeout_s),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "events" in data and data["events"]:
                            self.last_event_id = max(
                                data["events"], key=lambda e: e["eventId"]
                            )["eventId"]
                        return response
                    elif response.status in (502, 503, 504):
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2 ** attempt)
                            continue
                        return None
                    else:
                        return response
            except asyncio.TimeoutError:
                LOG.debug(f"Polling timeout after {poll_time_s}s (normal)")
            except aiohttp.ClientConnectorError as e:
                LOG.error(f"Connection failed in events_get: {e}")
            except aiohttp.ClientOSError as e:
                LOG.error(f"ClientOSError in events_get: {e}")
            except aiohttp.ServerDisconnectedError as e:
                LOG.error(f"Server disconnected during events_get: {e}")
            except Exception as e:
                LOG.exception(f"Unexpected error in events_get: {e}")
        return None

    async def send_text(
        self,
        chat_id: str,
        text: str,
        inline_keyboard_markup=None,
        parse_mode=None,
        format_=None,
    ):
        max_retries = 3
        if parse_mode and format_:
            raise Exception("Cannot use format and parseMode fields at one time")
        if parse_mode:
            ParseMode(parse_mode)

        data = {
            "token": self.token,
            "chatId": chat_id,
            "text": text,
        }
        if inline_keyboard_markup is not None:
            data["inlineKeyboardMarkup"] = keyboard_to_json(inline_keyboard_markup)
        if parse_mode is not None:
            data["parseMode"] = parse_mode
        if format_ is not None:
            data["format"] = format_to_json(format_)

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
