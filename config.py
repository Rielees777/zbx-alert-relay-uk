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
    # БД devnetops_oass_database (DB_*), которую наполняет отдельный проект
    # registry-pyrus-tasks — сам к Pyrus API этот сервис больше не ходит.
    db_host: str = Field(
        "float-dbass-db1.sovcombank.group", validation_alias=AliasChoices("DB_HOST", "db_host"),
    )
    db_port: int = Field(5432, validation_alias=AliasChoices("DB_PORT", "db_port"))
    db_name: str = Field(
        "devnetops_oass_database", validation_alias=AliasChoices("DB_NAME", "db_name"),
    )
    # Схема, в которой registry-pyrus-tasks держит pyrus_sites (та же
    # DB_SCHEMA, что и в его .env; по умолчанию public).
    db_schema:   str = Field("public", validation_alias=AliasChoices("DB_SCHEMA",   "db_schema"))
    db_user:     str = Field("", validation_alias=AliasChoices("DB_USER",     "db_user"))
    db_password: str = Field("", validation_alias=AliasChoices("DB_PASSWORD", "db_password"))

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

    @property
    def mail_enabled(self) -> bool:
        return bool(self.mail_service_url)

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
