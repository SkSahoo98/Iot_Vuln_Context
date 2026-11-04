"""Configuration for the MQTT → PostgreSQL collector.

Credentials come from environment variables / .env files — never from source code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent

def load_environment_files() -> None:
    """Load collector configuration with deterministic precedence.

    Highest to lowest precedence:
    1. Variables already present in the process environment
    2. backend/.env (the collector's intended configuration file)
    3. project-root .env (backward-compatible fallback for missing keys)

    python-dotenv does not override existing variables by default. Loading the
    backend file first therefore gives it precedence over the project-root
    fallback while still allowing explicit shell/service environment values.
    """
    load_dotenv(BACKEND_ROOT / ".env", override=False)
    load_dotenv(PROJECT_ROOT / ".env", override=False)


load_environment_files()


def _optional_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _parse_database_url(url: str) -> dict[str, str | int]:
    """Parse postgresql(+psycopg)://user:pass@host:port/dbname into parts."""
    cleaned = url.replace("postgresql+psycopg://", "postgresql://", 1)
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise RuntimeError("DATABASE_URL must be a postgresql URL")

    database = (parsed.path or "").lstrip("/")
    if not database:
        raise RuntimeError("DATABASE_URL is missing a database name")

    password = unquote(parsed.password) if parsed.password is not None else ""
    return {
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 5432,
        "database": database,
        "user": unquote(parsed.username) if parsed.username else "postgres",
        "password": password,
    }


def _resolve_postgres() -> dict[str, str | int]:
    """Prefer POSTGRES_* vars; fall back to DATABASE_URL for existing .env files."""
    explicit_password = (os.getenv("POSTGRES_PASSWORD") or "").strip()
    database_url = (os.getenv("DATABASE_URL") or "").strip()

    if explicit_password and explicit_password.upper() != "CHANGE_ME":
        return {
            "host": (os.getenv("POSTGRES_HOST") or "localhost").strip(),
            "port": _optional_int("POSTGRES_PORT", 5432),
            "database": (os.getenv("POSTGRES_DB") or "iot_security").strip(),
            "user": (os.getenv("POSTGRES_USER") or "postgres").strip(),
            "password": explicit_password,
        }

    if database_url and "CHANGE_ME" not in database_url:
        parsed = _parse_database_url(database_url)
        if not parsed["password"]:
            raise RuntimeError(
                "DATABASE_URL has no password. Set POSTGRES_PASSWORD in .env instead."
            )
        if os.getenv("POSTGRES_HOST"):
            parsed["host"] = os.getenv("POSTGRES_HOST", "").strip()
        if os.getenv("POSTGRES_PORT"):
            parsed["port"] = _optional_int("POSTGRES_PORT", int(parsed["port"]))
        if os.getenv("POSTGRES_DB"):
            parsed["database"] = os.getenv("POSTGRES_DB", "").strip()
        if os.getenv("POSTGRES_USER"):
            parsed["user"] = os.getenv("POSTGRES_USER", "").strip()
        return parsed

    raise RuntimeError(
        "Missing database credentials. Set POSTGRES_PASSWORD (recommended) "
        "or a complete DATABASE_URL in your .env file. "
        "See backend/.env.example — never commit real passwords."
    )


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the collector."""

    pg_host: str
    pg_port: int
    pg_database: str
    pg_user: str
    pg_password: str

    mqtt_broker_host: str
    mqtt_broker_port: int
    mqtt_topic: str
    mqtt_client_id: str
    mqtt_username: str | None
    mqtt_password: str | None

    db_pool_min_size: int
    db_pool_max_size: int

    @property
    def postgres_conninfo(self) -> str:
        """psycopg connection string (never log this — it contains the password)."""
        return (
            f"host={self.pg_host} "
            f"port={self.pg_port} "
            f"dbname={self.pg_database} "
            f"user={self.pg_user} "
            f"password={self.pg_password}"
        )


def load_settings(require_mqtt_auth: bool = False) -> Settings:
    """Build settings from environment variables."""
    pg = _resolve_postgres()
    min_size = _optional_int("DB_POOL_MIN_SIZE", 1)
    max_size = _optional_int("DB_POOL_MAX_SIZE", 4)
    if min_size < 1 or max_size < min_size:
        raise RuntimeError(
            "Invalid pool size: require DB_POOL_MIN_SIZE >= 1 and "
            "DB_POOL_MAX_SIZE >= DB_POOL_MIN_SIZE"
        )

    mqtt_username = (os.getenv("MQTT_USERNAME") or "").strip() or None
    mqtt_password = (os.getenv("MQTT_PASSWORD") or "").strip() or None

    if require_mqtt_auth and (not mqtt_username or not mqtt_password):
        raise RuntimeError(
            "MQTT authentication credentials missing. Set MQTT_USERNAME and MQTT_PASSWORD "
            "in your .env file or environment (anonymous access is not permitted)."
        )

    return Settings(
        pg_host=str(pg["host"]),
        pg_port=int(pg["port"]),
        pg_database=str(pg["database"]),
        pg_user=str(pg["user"]),
        pg_password=str(pg["password"]),
        mqtt_broker_host=os.getenv("MQTT_BROKER_HOST", "127.0.0.1").strip(),
        mqtt_broker_port=_optional_int("MQTT_BROKER_PORT", 1883),
        mqtt_topic=os.getenv("MQTT_TOPIC", "iot/esp32/+/sensor").strip(),
        mqtt_client_id=os.getenv(
            "MQTT_CLIENT_ID",
            "iot-security-mqtt-collector",
        ).strip(),
        mqtt_username=mqtt_username,
        mqtt_password=mqtt_password,
        db_pool_min_size=min_size,
        db_pool_max_size=max_size,
    )
