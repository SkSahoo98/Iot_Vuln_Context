"""Create the iot_security database if it does not exist.

Run from the backend directory after configuring .env:

    python scripts/create_database.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings  # noqa: E402


def main() -> None:
    settings = get_settings()
    target_url = make_url(settings.database_url)
    database_name = target_url.database

    if not database_name:
        raise SystemExit("DATABASE_URL must include a database name.")

    admin_url = make_url(settings.postgres_admin_url)
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")

    with admin_engine.connect() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :name"),
            {"name": database_name},
        ).scalar()

        if exists:
            print(f"Database '{database_name}' already exists.")
            return

        connection.execute(text(f'CREATE DATABASE "{database_name}"'))
        print(f"Database '{database_name}' created successfully.")


if __name__ == "__main__":
    main()
