from __future__ import annotations

import re

from models import ChannelInfo, PyrusSite

_POSTCODE_RE  = re.compile(r'\b\d{6}\b')
_ADDR_START_RE = re.compile(
    r'(?:\w+(?:ский|ская|ское|ской)\s+(?:край|обл(?:асть)?)|'
    r'(?:г(?:ород)?|гор)\s*\.?\s*[А-ЯЁ])',
    re.IGNORECASE,
)


def _extract_addr_from_short_name(raw: str) -> str | None:
    m = _POSTCODE_RE.search(raw)
    if m:
        addr = raw[m.end():].strip().lstrip(",").strip()
        if len(addr) > 10:
            return addr
    m = _ADDR_START_RE.search(raw)
    if m:
        addr = raw[m.start():].strip()
        if len(addr) > 10:
            return addr
    return None


class PyrusSiteParser:

    @classmethod
    def parse(cls, raw: dict) -> PyrusSite:
        fields = {f["id"]: f for f in raw.get("fields", [])}
        return PyrusSite(
            task_id         = raw["id"],
            directorate     = cls._catalog_val(fields, fid=1, col=0),
            zabbix_hostname = cls._text_val(fields, fid=8),
            router_ip       = cls._text_val(fields, fid=9),
            city            = cls._catalog_val(fields, fid=6, col=3),
            **cls._resolve_address(fields),
            channels        = cls._parse_channels(fields),
        )

    @classmethod
    def parse_many(cls, tasks: list[dict], uk_only: bool = False) -> list[PyrusSite]:
        sites = [cls.parse(t) for t in tasks]
        return [s for s in sites if s.is_uk] if uk_only else sites

    @classmethod
    def _resolve_address(cls, fields: dict) -> dict:
        candidates: list[tuple[str, str]] = []

        if addr := cls._catalog_val(fields, fid=6, col=4):
            city = cls._catalog_val(fields, fid=6, col=3) or ""
            if city and city.lower() not in addr.lower():
                addr = f"{city}, {addr}"
            candidates.append((addr, "catalog"))

        if addr := cls._text_val(fields, fid=7):
            candidates.append((addr, "free_text"))

        if not candidates:
            if addr := cls._extract_from_col2(fields):
                candidates.append((addr, "extracted"))

        if not candidates:
            return {"address": None, "address_source": None}

        best_addr, best_source = max(candidates, key=lambda x: len(x[0]))
        return {"address": best_addr, "address_source": best_source}

    @classmethod
    def _extract_from_col2(cls, fields: dict) -> str | None:
        short = cls._catalog_val(fields, fid=6, col=2)
        return _extract_addr_from_short_name(short) if short else None

    @classmethod
    def _parse_channels(cls, fields: dict) -> list[ChannelInfo]:
        table = fields.get(41)
        if not table or not isinstance(table.get("value"), list):
            return []
        result = []
        for row in table["value"]:
            cells = {c["id"]: c for c in row.get("cells", [])}
            ch = ChannelInfo(
                provider   = cls._cell_catalog(cells, cid=42, col=1),
                channel_id = cls._cell_text(cells, cid=43),
                bandwidth  = cls._cell_int(cells, cid=44),
                contract   = cls._cell_text(cells, cid=46),
                ip_address = cls._cell_text(cells, cid=47),
                service    = cls._cell_choice(cells, cid=49),
                technology = cls._cell_catalog(cells, cid=50, col=1),
            )
            if ch.provider or ch.channel_id:
                result.append(ch)
        return result

    @staticmethod
    def _text_val(fields: dict, fid: int) -> str | None:
        f = fields.get(fid)
        v = f.get("value") if f else None
        return v.strip() if isinstance(v, str) and v.strip() not in ("", "-") else None

    @staticmethod
    def _catalog_val(fields: dict, fid: int, col: int) -> str | None:
        f = fields.get(fid)
        try:
            v = f["value"]["values"][col]
            return v.strip() if v and v.strip() not in ("", "-") else None
        except (KeyError, IndexError, TypeError):
            return None

    @staticmethod
    def _cell_text(cells: dict, cid: int) -> str | None:
        c = cells.get(cid)
        v = c.get("value") if c else None
        return v.strip() if isinstance(v, str) and v.strip() not in ("", "-") else None

    @staticmethod
    def _cell_int(cells: dict, cid: int) -> int | None:
        c = cells.get(cid)
        try:
            return int(c["value"])
        except (KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def _cell_catalog(cells: dict, cid: int, col: int) -> str | None:
        c = cells.get(cid)
        try:
            v = c["value"]["values"][col]
            return v.strip() if v and v.strip() not in ("", "-") else None
        except (KeyError, IndexError, TypeError):
            return None

    @staticmethod
    def _cell_choice(cells: dict, cid: int) -> str | None:
        """Ячейка-выпадающее меню (multiple_choice): берём первый выбранный пункт."""
        c = cells.get(cid)
        try:
            v = c["value"]["choice_names"][0]
            return v.strip() if v and v.strip() not in ("", "-") else None
        except (KeyError, IndexError, TypeError):
            return None
