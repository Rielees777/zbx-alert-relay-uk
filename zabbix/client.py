from __future__ import annotations

from pyzabbix import ZabbixAPI

from models import ZabbixConfig


class ZabbixClient:
    def __init__(self, config: ZabbixConfig) -> None:
        self._config: ZabbixConfig    = config
        self._zapi:   ZabbixAPI | None = None

    def connect(self) -> "ZabbixClient":
        zapi = ZabbixAPI(self._config.url)
        zapi.session.verify = self._config.ssl_verify
        zapi.timeout        = self._config.timeout

        if self._config.use_token:
            zapi.login(api_token=self._config.api_token)
        else:
            zapi.login(self._config.user, self._config.password)

        self._zapi = zapi
        return self

    def disconnect(self) -> None:
        if self._zapi is not None:
            try:
                self._zapi.user.logout()
            except Exception:
                pass
            finally:
                self._zapi = None

    def __enter__(self) -> "ZabbixClient":
        return self.connect()

    def __exit__(self, *_: object) -> None:
        self.disconnect()

    @property
    def is_connected(self) -> bool:
        return self._zapi is not None

    def _ensure_connected(self) -> None:
        if self._zapi is None:
            raise RuntimeError(
                "Not connected to Zabbix. Call connect() or use as a context manager."
            )
