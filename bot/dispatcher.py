import logging
import asyncio


class Dispatcher:
    def __init__(self, bot):
        self.log = logging.getLogger(__name__)
        self.bot = bot
        self.handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def remove_handler(self, handler):
        if handler in self.handlers:
            self.handlers.remove(handler)

    async def dispatch(self, event):
        try:
            self.log.debug(f"Dispatching event '{event}'.")
            for handler in (h for h in self.handlers if h.check(event=event, dispatcher=self)):
                await handler.handle(event=event, dispatcher=self)
        except StopDispatching:
            self.log.debug(f"Caught 'StopDispatching' exception, stopping dispatching.")
        except Exception:
            self.log.exception("Exception while dispatching event!")


class StopDispatching(Exception):
    pass
