from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


@lru_cache
def get_engine(dsn: str) -> Engine:
    return create_engine(dsn, pool_pre_ping=True)


@lru_cache
def _session_factory(dsn: str) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(dsn), expire_on_commit=False)


@contextmanager
def get_session(dsn: str) -> Iterator[Session]:
    session = _session_factory(dsn)()
    try:
        yield session
    finally:
        session.close()
