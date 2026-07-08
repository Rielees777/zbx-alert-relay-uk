from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from db.models import PyrusSiteRow
from models import ChannelInfo, PyrusSite


def load_sites(session: Session) -> list[PyrusSite]:
    """Читает реестр каналов связи Pyrus из БД (наполняется registry-pyrus-tasks)
    и возвращает его в виде тех же моделей данных, что раньше отдавал PyrusSiteParser."""
    rows = session.scalars(
        select(PyrusSiteRow).options(selectinload(PyrusSiteRow.channels)),
    ).all()

    return [
        PyrusSite(
            task_id=row.task_id,
            directorate=row.directorate,
            zabbix_hostname=row.zabbix_hostname,
            router_ip=row.router_ip,
            address=row.address,
            address_source=row.address_source,
            city=row.city,
            channels=[
                ChannelInfo(
                    provider=ch.provider,
                    channel_id=ch.channel_id,
                    bandwidth=ch.bandwidth,
                    contract=ch.contract,
                    ip_address=ch.ip_address,
                    service=ch.service,
                    technology=ch.technology,
                )
                for ch in row.channels
            ],
        )
        for row in rows
    ]
