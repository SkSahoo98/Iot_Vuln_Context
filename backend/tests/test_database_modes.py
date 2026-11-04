"""Unit tests for database connection pool selection (Local QueuePool vs Neon/Vercel NullPool).

These tests run entirely offline without requiring a live connection to PostgreSQL or Neon.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from unittest import mock

import pytest
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool, QueuePool

from app.core.database import (
    create_database_engine,
    get_db,
    get_engine_options,
    is_production_mode,
)


@pytest.fixture(scope="session", autouse=True)
def require_database() -> Generator[None, None, None]:
    """Override tests/conftest.py session fixture so these engine mode tests run offline."""
    yield


class TestDatabasePoolSelection:
    """Verify adaptive pooling selection between local development and production/serverless."""

    def test_default_mode_selects_queue_pool(self) -> None:
        """In local development without production flags, QueuePool with standard bounds must be chosen."""
        with mock.patch.dict(os.environ, {}, clear=True):
            options = get_engine_options("sqlite:///:memory:", is_production=False)
            assert options["poolclass"] is QueuePool
            assert options["pool_pre_ping"] is True
            assert options["pool_size"] == 30
            assert options["max_overflow"] == 50
            assert options["pool_timeout"] == 60
            assert options["echo"] is False

    def test_production_environment_selects_null_pool(self) -> None:
        """When ENVIRONMENT is set to production, NullPool must be selected for serverless efficiency."""
        with mock.patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            assert is_production_mode("postgresql+psycopg://user:pass@localhost:5432/db") is True
            options = get_engine_options("sqlite:///:memory:")
            assert options["poolclass"] is NullPool
            assert options["pool_pre_ping"] is True
            assert options["echo"] is False
            assert "pool_size" not in options
            assert "max_overflow" not in options
            assert "pool_timeout" not in options

    def test_staging_environment_selects_null_pool(self) -> None:
        """Staging environments also use NullPool to match production serverless behavior."""
        with mock.patch.dict(os.environ, {"ENVIRONMENT": "staging"}):
            assert is_production_mode("postgresql+psycopg://user:pass@localhost:5432/db") is True
            options = get_engine_options("sqlite:///:memory:")
            assert options["poolclass"] is NullPool

    def test_vercel_environment_safeguard_triggers_null_pool(self) -> None:
        """Setting VERCEL=1 must trigger NullPool regardless of local ENVIRONMENT setting."""
        with mock.patch.dict(os.environ, {"VERCEL": "1", "ENVIRONMENT": "development"}):
            assert is_production_mode() is True
            options = get_engine_options("sqlite:///:memory:")
            assert options["poolclass"] is NullPool

    def test_vercel_env_flag_safeguard_triggers_null_pool(self) -> None:
        """Setting VERCEL_ENV must trigger NullPool."""
        with mock.patch.dict(os.environ, {"VERCEL_ENV": "preview", "ENVIRONMENT": "development"}):
            assert is_production_mode() is True
            options = get_engine_options("sqlite:///:memory:")
            assert options["poolclass"] is NullPool

    def test_neon_pooler_url_safeguard_triggers_null_pool(self) -> None:
        """Any connection string referencing a Neon '-pooler' endpoint must default to NullPool."""
        neon_pooler_url = "postgresql+psycopg://user:secret@ep-cool-project-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"
        with mock.patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            assert is_production_mode(neon_pooler_url) is True
            options = get_engine_options(neon_pooler_url)
            assert options["poolclass"] is NullPool

    def test_explicit_override_db_pool_type_nullpool(self) -> None:
        """Explicit DB_POOL_TYPE=nullpool overrides development environment."""
        with mock.patch.dict(os.environ, {"DB_POOL_TYPE": "nullpool", "ENVIRONMENT": "development"}):
            assert is_production_mode() is True
            options = get_engine_options("sqlite:///:memory:")
            assert options["poolclass"] is NullPool

    def test_explicit_override_db_pool_type_queuepool(self) -> None:
        """Explicit DB_POOL_TYPE=queuepool forces QueuePool even if ENVIRONMENT=production."""
        with mock.patch.dict(os.environ, {"DB_POOL_TYPE": "queuepool", "ENVIRONMENT": "production"}):
            assert is_production_mode() is False
            options = get_engine_options("sqlite:///:memory:")
            assert options["poolclass"] is QueuePool
            assert options["pool_size"] == 30

    def test_engine_creation_and_session_lifecycle(self) -> None:
        """Engines created in both modes must support standard session operations."""
        # QueuePool engine
        local_engine = create_database_engine("sqlite:///:memory:", is_production=False)
        assert isinstance(local_engine.pool, QueuePool)

        # NullPool engine
        prod_engine = create_database_engine("sqlite:///:memory:", is_production=True)
        assert isinstance(prod_engine.pool, NullPool)

        # Test session dependency lifecycle with in-memory DB
        with mock.patch("app.core.database.SessionLocal") as mock_session_local:
            mock_session = mock.MagicMock(spec=Session)
            mock_session_local.return_value = mock_session

            gen = get_db()
            session = next(gen)
            assert session is mock_session
            try:
                next(gen)
            except StopIteration:
                pass
            mock_session.close.assert_called_once()
