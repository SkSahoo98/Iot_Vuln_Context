"""SQLAlchemy engine and session factory with adaptive pooling for Local vs Neon/Vercel."""

from __future__ import annotations

import os
from collections.abc import Generator
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from app.core.config import get_settings

settings = get_settings()


def is_production_mode(database_url: str | None = None) -> bool:
    """Determine whether the application is running in production/serverless mode.

    Detection priority:
    1. Explicit override via DB_POOL_TYPE ('nullpool' -> True, 'queuepool' -> False).
    2. Vercel serverless environment indicators (VERCEL or VERCEL_ENV set).
    3. Explicit environment setting (ENVIRONMENT in {'production', 'prod', 'staging'}).
    4. Neon connection pooler hostname safeguard ('-pooler' present in database_url).
    """
    pool_override = os.getenv("DB_POOL_TYPE", "").strip().lower()
    if pool_override == "nullpool":
        return True
    if pool_override == "queuepool":
        return False

    # Vercel environment detection safeguard
    if os.getenv("VERCEL") or os.getenv("VERCEL_ENV"):
        return True

    # Explicit environment setting (production / prod / staging)
    env_name = os.getenv("ENVIRONMENT") or getattr(settings, "environment", "development")
    if str(env_name).strip().lower() in {"production", "prod", "staging"}:
        return True

    # Neon PgBouncer connection pooler safeguard
    url_to_check = database_url or getattr(settings, "database_url", "") or ""
    if "-pooler" in url_to_check:
        return True

    return False


def get_engine_options(
    database_url: str | None = None,
    is_production: bool | None = None,
) -> dict[str, Any]:
    """Return appropriate create_engine keyword arguments for the runtime environment."""
    if is_production is None:
        is_production = is_production_mode(database_url)

    if is_production:
        # Neon / Vercel Serverless Production mode:
        # NullPool delegates connection multiplexing to Neon's upstream PgBouncer
        # and avoids holding idle connections in ephemeral serverless containers.
        return {
            "poolclass": NullPool,
            "pool_pre_ping": True,
            "echo": False,
        }

    # Local development mode:
    # Retains existing persistent connection pool configuration.
    return {
        "poolclass": QueuePool,
        "pool_pre_ping": True,
        "pool_size": 30,
        "max_overflow": 50,
        "pool_timeout": 60,
        "echo": False,
    }


def create_database_engine(
    database_url: str | None = None,
    is_production: bool | None = None,
) -> Engine:
    """Factory to create an Engine configured for either local dev or Neon/Vercel production."""
    url = database_url or settings.database_url
    options = get_engine_options(url, is_production=is_production)
    return create_engine(url, **options)


# Default application engine, session factory, and FastAPI dependency
engine = create_database_engine()

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
