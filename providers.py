from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Ячейка email техподдержки провайдера в Pyrus (ChannelInfo.email, cell 52)
# нередко содержит ещё и телефон вперемешку (через запятую/перенос строки/
# пробел) — вытаскиваем только email.
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def extract_email(text: str | None) -> str | None:
    """Первый email из свободнотекстовой ячейки (ChannelInfo.email) — там
    кроме email нередко указан ещё и телефон."""
    if not text:
        return None
    m = _EMAIL_RE.search(text)
    return m.group(0) if m else None


PROVIDER_ALIASES: dict[str, str] = {
    # МТС
    "mts":                   "МТС",
    "мтс":                   "МТС",
    "мобильные телесистемы": "МТС",

    # МегаФон
    "megafon":               "МегаФон",
    "мегафон":               "МегаФон",

    # ВымпелКом / Билайн
    "beeline":               "ВымпелКом",
    "vimpelcom":             "ВымпелКом",
    "вымпелком":             "ВымпелКом",

    # Ростелеком
    "rt":                    "Ростелеком",
    "ртк":                   "Ростелеком",
    "ростелеком":            "Ростелеком",
    "rostelecom":            "Ростелеком",

    # ТТК
    "ttk":                   "ТТК",
    "ттк":                   "ТТК",
    "транстелеком":          "ТТК",

    # МегаКом
    "megacom":               "МегаКом",
    "мегаком":               "МегаКом",
    "мегаком-ит":            "МегаКом",

    # Обит
    "obit":                  "Обит",
    "обит":                  "Обит",

    # Авантел
    "avantel":               "Авантел",
    "авантел":               "Авантел",

    # Орион телеком
    "orion":                 "Орион телеком",
    "oriontelecom":          "Орион телеком",
    "орион":                 "Орион телеком",
    "орион телеком":         "Орион телеком",

    # Оранж Бизнес Сервисез (бывший Эквант; в описаниях каналов часто
    # подписан как "eqvant" — транслитерация старого названия Equant)
    "orange":                "Оранж Бизнес Сервисез",
    "eqvant":                "Оранж Бизнес Сервисез",
    "equant":                "Оранж Бизнес Сервисез",
    "эквант":                "Оранж Бизнес Сервисез",
    "оранж":                 "Оранж Бизнес Сервисез",
    "оранж бизнес сервисез": "Оранж Бизнес Сервисез",
}


def _clean_key(raw: str) -> str:
    key = raw.lower().replace("ё", "е")
    key = re.sub(r'\b(пао|оао|ооо|зао|ао)\b', '', key)
    key = re.sub(r'["\'\«\»]', '', key)
    key = re.sub(r'\s+', ' ', key).strip()
    return key


def is_aliased(raw: str | None) -> bool:
    """True, если raw резолвится через реальную запись в PROVIDER_ALIASES,
    а не просто возвращается как есть (см. normalize_provider fallback)."""
    if not raw:
        return False
    key = _clean_key(raw)
    return key in PROVIDER_ALIASES or any(alias in key for alias in PROVIDER_ALIASES)


def normalize_provider(raw: str | None) -> str | None:
    """
    Нормализует любое написание провайдера → каноническое имя.
    'ttk' → 'ТТК',  'ПАО МобильныеТелеСистемы' → 'МТС'.
    Возвращает None если raw пустой, иначе canonical или raw.strip().
    """
    if not raw:
        return None

    key = _clean_key(raw)

    if key in PROVIDER_ALIASES:
        return PROVIDER_ALIASES[key]

    for alias, canonical in PROVIDER_ALIASES.items():
        if alias in key:
            return canonical

    logger.warning(
        "Неизвестный провайдер: %r — нет алиаса в PROVIDER_ALIASES (providers.py). "
        "Если это реальный провайдер из триггера/Pyrus, из-за разного написания "
        "(латиница/кириллица, транслитерация) канал не сматчится и договор не найдётся — "
        "добавьте пару 'слаг из триггера': 'каноническое имя из Pyrus'.",
        raw,
    )
    return raw.strip()
