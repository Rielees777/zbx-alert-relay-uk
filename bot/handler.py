import asyncio
import logging
from abc import ABCMeta

import six

from .dispatcher import StopDispatching
from .event import EventType
from .filter import Filter


@six.add_metaclass(ABCMeta)
class HandlerBase:
    def __init__(self, filters=None, callback=None):
        self.filters = filters
        self.callback = callback
        self.log = logging.getLogger(__name__)

    def check(self, event, dispatcher):
        return bool(not self.filters or self.filters(event))

    async def handle(self, event, dispatcher):
        if self.callback:
            if asyncio.iscoroutinefunction(self.callback):
                await self.callback(bot=dispatcher.bot, event=event)
            else:
                self.log.warning("Synchronous callback detected. Please use async callbacks.")
                self.callback(bot=dispatcher.bot, event=event)


class MessageHandler(HandlerBase):
    def check(self, event, dispatcher):
        return (
            super(MessageHandler, self).check(event=event, dispatcher=dispatcher) and
            event.type == EventType.NEW_MESSAGE
        )


class BotButtonCommandHandler(HandlerBase):
    def check(self, event, dispatcher):
        return (
            super(BotButtonCommandHandler, self).check(event=event, dispatcher=dispatcher) and
            event.type is EventType.CALLBACK_QUERY
        )


class EditedMessageHandler(HandlerBase):
    def check(self, event, dispatcher):
        return (
            super(EditedMessageHandler, self).check(event=event, dispatcher=dispatcher) and
            event.type == EventType.EDITED_MESSAGE
        )
