"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.models import Base, Device, Finding, RiskFactorValue, RiskScore  # noqa: E402


@pytest.fixture(scope="session")
def settings():
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture(scope="session")
def engine(settings):
    return create_engine(settings.database_url, pool_pre_ping=True)


@pytest.fixture(scope="session")
def db_session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture()
def db_session(db_session_factory) -> Generator[Session, None, None]:
    session = db_session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="session", autouse=True)
def require_database(engine) -> None:
    """Skip the suite if PostgreSQL is not reachable."""
    if os.getenv("SKIP_DB_TESTS") == "1":
        pytest.skip("Database tests skipped by SKIP_DB_TESTS=1")
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"PostgreSQL not available: {exc}")
