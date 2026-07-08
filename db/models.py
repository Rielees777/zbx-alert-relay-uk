from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class PyrusSiteRow(Base):
    """Задача реестра каналов связи Pyrus — таблица наполняется проектом
    registry-pyrus-tasks, здесь читается только на чтение."""

    __tablename__ = "pyrus_sites"

    task_id:         Mapped[int]        = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    directorate:     Mapped[str | None] = mapped_column(String(255))
    zabbix_hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    router_ip:       Mapped[str | None] = mapped_column(String(64), index=True)
    address:         Mapped[str | None] = mapped_column(String(1024))
    address_source:  Mapped[str | None] = mapped_column(String(32))
    city:            Mapped[str | None] = mapped_column(String(255))
    updated_at:      Mapped[datetime]   = mapped_column(DateTime(timezone=True))

    channels: Mapped[list["PyrusChannelRow"]] = relationship(back_populates="site")


class PyrusChannelRow(Base):
    """Строка таблицы каналов связи задачи (models.ChannelInfo)."""

    __tablename__ = "pyrus_channels"

    id:          Mapped[int]        = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id:     Mapped[int]        = mapped_column(BigInteger, ForeignKey("pyrus_sites.task_id"), index=True)
    provider:    Mapped[str | None] = mapped_column(String(255))
    channel_id:  Mapped[str | None] = mapped_column(String(255))
    bandwidth:   Mapped[int | None] = mapped_column(Integer)
    contract:    Mapped[str | None] = mapped_column(String(255))
    ip_address:  Mapped[str | None] = mapped_column(String(64))
    service:     Mapped[str | None] = mapped_column(String(255))
    technology:  Mapped[str | None] = mapped_column(String(255))

    site: Mapped[PyrusSiteRow] = relationship(back_populates="channels")
