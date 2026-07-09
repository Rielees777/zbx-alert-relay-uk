from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from models import ZabbixConfig


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ZABBIX_",
        extra="ignore",
        populate_by_name=True,
    )

    # Zabbix (ZABBIX_*)
    url:        str
    token:      str
    verify_ssl: bool = True

    # Уровень логирования (LOG_LEVEL=DEBUG для подробного разбора
    # сопоставления Pyrus — matcher/find_channel_by_trigger/_contract).
    log_level: str = Field("INFO", validation_alias=AliasChoices("LOG_LEVEL", "log_level"))

    # Реестр каналов связи Pyrus читается из таблицы pyrus_sites в готовой
    # БД devnetops_oass_database (DB_*). Эту таблицу наполняет сам сервис —
    # см. pyrus_sync.py и db_write/ — раз в сутки по расписанию (scheduler.py).
    db_host: str = Field(
        "float-dbass-db1.sovcombank.group", validation_alias=AliasChoices("DB_HOST", "db_host"),
    )
    db_port: int = Field(5432, validation_alias=AliasChoices("DB_PORT", "db_port"))
    db_name: str = Field(
        "devnetops_oass_database", validation_alias=AliasChoices("DB_NAME", "db_name"),
    )
    # Отдельная схема под реестр Pyrus вместо public (создаётся автоматически).
    db_schema:     str = Field("public", validation_alias=AliasChoices("DB_SCHEMA",     "db_schema"))
    db_user:       str = Field("", validation_alias=AliasChoices("DB_USER",       "db_user"))
    db_password:   str = Field("", validation_alias=AliasChoices("DB_PASSWORD",   "db_password"))
    # Размер батча при upsert реестра в БД.
    db_batch_size: int = Field(1000, validation_alias=AliasChoices("DB_BATCH_SIZE", "db_batch_size"))

    # Pyrus API (PYRUS_*) — источник данных для ежедневной синхронизации
    # реестра каналов связи в pyrus_sites (pyrus_sync.sync_registry).
    pyrus_login:   str  = Field("",    validation_alias=AliasChoices("PYRUS_LOGIN",   "pyrus_login"))
    pyrus_token:   str  = Field("",    validation_alias=AliasChoices("PYRUS_TOKEN",   "pyrus_token"))
    pyrus_form_id: int  = Field(0,     validation_alias=AliasChoices("PYRUS_FORM_ID", "pyrus_form_id"))
    # Выгружать только задачи УК-* (PyrusSite.is_uk).
    pyrus_uk_only: bool = Field(False, validation_alias=AliasChoices("PYRUS_UK_ONLY", "pyrus_uk_only"))
    # Время ежедневного запуска синхронизации реестра Pyrus (локальное
    # время процесса), см. scheduler.py.
    pyrus_sync_hour:   int = Field(3, validation_alias=AliasChoices("PYRUS_SYNC_HOUR",   "pyrus_sync_hour"))
    pyrus_sync_minute: int = Field(0, validation_alias=AliasChoices("PYRUS_SYNC_MINUTE", "pyrus_sync_minute"))

    @property
    def pyrus_configured(self) -> bool:
        return bool(self.pyrus_login and self.pyrus_token and self.pyrus_form_id)

    # Juniper / PyEZ (JUNOS_*)
    junos_user:     str = Field("",  validation_alias=AliasChoices("JUNOS_USER",     "junos_user"))
    junos_password: str = Field("",  validation_alias=AliasChoices("JUNOS_PASSWORD", "junos_password"))
    junos_port:     int = Field(22,  validation_alias=AliasChoices("JUNOS_PORT",     "junos_port"))
    junos_timeout:  int = Field(30,  validation_alias=AliasChoices("JUNOS_TIMEOUT",  "junos_timeout"))

    # VK Teams / ICQ бот (BOT_*)
    bot_token:   str = Field("", validation_alias=AliasChoices("BOT_TOKEN",   "bot_token"))
    bot_url:     str = Field("", validation_alias=AliasChoices("BOT_URL",     "bot_url"))
    bot_proxy:   str = Field("", validation_alias=AliasChoices("BOT_PROXY",   "bot_proxy"))
    bot_chat_id: str = Field("", validation_alias=AliasChoices("BOT_CHAT_ID", "bot_chat_id"))

    # Почта оператору через mail-service по HTTP (MAIL_*)
    mail_service_url: str = Field("",           validation_alias=AliasChoices("MAIL_SERVICE_URL", "mail_service_url"))
    mailbox:          str = Field("isptt_init", validation_alias=AliasChoices("MAILBOX",          "mailbox"))
    mail_verify_ssl:  bool = Field(True,        validation_alias=AliasChoices("MAIL_VERIFY_SSL",  "mail_verify_ssl"))
    # Запасной адрес получателя, если провайдер не найден в PROVIDER_EMAILS.
    mail_to_default:  str = Field("",           validation_alias=AliasChoices("MAIL_TO_DEFAULT",  "mail_to_default"))
    # Адреса копии письма оператору, через запятую (необязательно).
    mail_cc:          str = Field("",           validation_alias=AliasChoices("MAIL_CC",          "mail_cc"))

    @property
    def mail_enabled(self) -> bool:
        return bool(self.mail_service_url)

    @property
    def mail_cc_list(self) -> list[str]:
        return [addr.strip() for addr in self.mail_cc.split(",") if addr.strip()]

    def zabbix_config(self) -> ZabbixConfig:
        return ZabbixConfig(
            url=self.url,
            api_token=self.token,
            ssl_verify=self.verify_ssl,
        )

    def junos_kwargs(self, host: str) -> dict:
        return {
            "host":              host,
            "user":              self.junos_user,
            "passwd":            self.junos_password,
            "port":              self.junos_port,
            "conn_open_timeout": self.junos_timeout,
        }
