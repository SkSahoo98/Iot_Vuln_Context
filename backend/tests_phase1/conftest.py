"""Isolated Phase 1 fixtures; does not import the obsolete 24-table models."""

from __future__ import annotations

import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
for path in (BACKEND_ROOT, PROJECT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.core.config import Settings, get_settings  # noqa: E402

REQUIRED_ASSESSMENT_TABLES = {
    "assessment_runs",
    "assessment_evidence",
    "assessment_findings",
    "risk_snapshots",
    "remediation_workflows",
    "remediation_verifications",
}


@pytest.fixture(scope="session")
def engine():
    runtime = get_settings()
    engine = create_engine(runtime.database_url, pool_pre_ping=True)
    missing = REQUIRED_ASSESSMENT_TABLES - set(inspect(engine).get_table_names())
    if missing:
        pytest.fail(
            "Assessment schema is not applied. Run "
            "backend\\.venv\\Scripts\\python.exe "
            "backend\\scripts\\apply_assessment_schema.py. "
            f"Missing: {sorted(missing)}"
        )
    return engine


@pytest.fixture()
def db_session(engine) -> Generator[Session, None, None]:
    """Use savepoints so service-level commits never escape the test."""
    connection = engine.connect()
    outer_transaction = connection.begin()
    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        session.close()
        if outer_transaction.is_active:
            outer_transaction.rollback()
        connection.close()


@pytest.fixture()
def phase1_settings() -> Settings:
    runtime = get_settings()
    return Settings(
        _env_file=None,
        DATABASE_URL=runtime.database_url,
        ASSESSMENT_ALLOWED_TARGETS="10.84.237.85,127.0.0.250",
        ASSESSMENT_PORTS="21,22,23,80,443,1883,8080,8443,8883",
        ASSESSMENT_MAX_OPEN_SERVICES=5,
        ASSESSMENT_ADMIN_SERVICE_PORTS="22",
        ASSESSMENT_PROBE_TIMEOUT_SECONDS=0.1,
        NMAP_TIMEOUT_SECONDS=5,
    )
