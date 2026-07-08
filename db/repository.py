from __future__ import annotations

from psycopg2.extensions import connection as PGConnection

from models import ChannelInfo, PyrusSite

_SELECT_SQL = """
SELECT task_id, directorate, zabbix_hostname, router_ip, address, address_source, city, channels
FROM pyrus_sites
"""


def load_sites(conn: PGConnection) -> list[PyrusSite]:
    """Читает реестр каналов связи Pyrus из таблицы pyrus_sites (наполняется
    проектом registry-pyrus-tasks) и возвращает его в виде тех же моделей
    данных, что раньше отдавал PyrusSiteParser."""
    with conn.cursor() as cur:
        cur.execute(_SELECT_SQL)
        rows = cur.fetchall()

    return [
        PyrusSite(
            task_id=task_id,
            directorate=directorate,
            zabbix_hostname=zabbix_hostname,
            router_ip=router_ip,
            address=address,
            address_source=address_source,
            city=city,
            channels=[ChannelInfo(**ch) for ch in (channels or [])],
        )
        for task_id, directorate, zabbix_hostname, router_ip, address, address_source, city, channels in rows
    ]
