"""Apply the additive Phase 1 assessment schema without Alembic.

Usage (from repository root):
    backend\\.venv\\Scripts\\python.exe backend\\scripts\\apply_assessment_schema.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings  # noqa: E402


def main() -> int:
    settings = get_settings()
    schema_path = PROJECT_ROOT / "database" / "assessment_schema.sql"
    sql = schema_path.read_text(encoding="utf-8")
    connection_url = settings.database_url.replace(
        "postgresql+psycopg://",
        "postgresql://",
        1,
    )

    with psycopg.connect(connection_url) as connection:
        # psycopg's simple-query protocol supports the idempotent SQL file as
        # one batch. No existing table is dropped or altered.
        connection.execute(sql, prepare=False)
    print("Assessment schema applied successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
