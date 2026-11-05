"""Configuration for the MQTT → PostgreSQL collector.

Credentials come from environment variables / .env files — never from source code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from dotenv import dotenv_values, load_dotenv
from psycopg.conninfo import conninfo_to_dict, make_conninfo

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent

# Snapshot the keys present in os.environ before loading any .env files
_INITIAL_PROCESS_ENV: set[str] = set(os.environ.keys())


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
    global _INITIAL_PROCESS_ENV
    _INITIAL_PROCESS_ENV.update(os.environ.keys())
    load_dotenv(BACKEND_ROOT / ".env", override=False)
    load_dotenv(PROJECT_ROOT / ".env", override=False)


load_environment_files()


def _is_process_level_database_url() -> bool:
    """Check if DATABASE_URL was supplied in the process environment rather than loaded from .env."""
    current = os.getenv("DATABASE_URL")
    if not current or not current.strip():
        return False

    current_val = current.strip()
    if "DATABASE_URL" in _INITIAL_PROCESS_ENV:
        return True

    file_urls: list[str] = []
    for env_path in (BACKEND_ROOT / ".env", PROJECT_ROOT / ".env"):
        if env_path.is_file():
            try:
                val = dotenv_values(env_path).get("DATABASE_URL")
                if val and val.strip():
                    file_urls.append(val.strip())
            except Exception:
                pass

    if not file_urls:
        return True

    return current_val not in file_urls


def _optional_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _parse_database_url(url: str) -> dict[str, Any]:
    """Parse postgresql(+psycopg)://user:pass@host:port/dbname?sslmode=... into parts.

    Preserves standard parameters (host, port, dbname, user, password) as well as
    connection options such as sslmode, connect_timeout, etc.
    """
    cleaned = url.strip()
    if cleaned.startswith("postgresql+psycopg://"):
        cleaned = "postgresql://" + cleaned[len("postgresql+psycopg://") :]
    elif cleaned.startswith("postgresql+psycopg3://"):
        cleaned = "postgresql://" + cleaned[len("postgresql+psycopg3://") :]

    parsed_url = urlparse(cleaned)
    if parsed_url.scheme not in {"postgresql", "postgres"}:
        raise RuntimeError("DATABASE_URL must be a postgresql URL")

    try:
        conninfo_params = conninfo_to_dict(cleaned)
    except Exception:
        raise RuntimeError("Invalid DATABASE_URL format") from None

    database = conninfo_params.get("dbname") or (parsed_url.path or "").lstrip("/")
    if not database:
        raise RuntimeError("DATABASE_URL is missing a database name")

    host = conninfo_params.get("host") or parsed_url.hostname or "localhost"
    try:
        port = int(conninfo_params.get("port") or parsed_url.port or 5432)
    except (ValueError, TypeError):
        port = 5432

    user = conninfo_params.get("user") or (unquote(parsed_url.username) if parsed_url.username else "postgres")
    password = conninfo_params.get("password") or (unquote(parsed_url.password) if parsed_url.password is not None else "")

    standard_keys = {"host", "port", "dbname", "user", "password"}
    extra_params = {k: v for k, v in conninfo_params.items() if k not in standard_keys}

    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "database": database,
        "user": user,
        "password": password,
    }
    if "sslmode" in extra_params:
        result["sslmode"] = extra_params.pop("sslmode")
    if extra_params:
        result["extra_params"] = extra_params

    return result


def _resolve_postgres() -> dict[str, Any]:
    """Resolve PostgreSQL settings with strict precedence.

    1. Process-level DATABASE_URL:
       If DATABASE_URL was set in the process environment (e.g. for Neon cloud database),
       it takes absolute precedence over .env files. Query parameters such as sslmode
       are preserved, and .env local variables cannot override or corrupt it.
    2. Explicit POSTGRES_* credentials:
       If POSTGRES_PASSWORD is set (and not CHANGE_ME), use individual POSTGRES_* vars.
    3. File-level DATABASE_URL from .env:
       Fallback to DATABASE_URL defined in .env files, allowing local POSTGRES_* overrides.
    """
    database_url = (os.getenv("DATABASE_URL") or "").strip()

    # 1. Process environment DATABASE_URL override
    if _is_process_level_database_url() and "CHANGE_ME" not in database_url:
        parsed = _parse_database_url(database_url)
        if not parsed.get("password"):
            raise RuntimeError(
                "DATABASE_URL has no password. Set POSTGRES_PASSWORD in .env instead."
            )
        return parsed

    # 2. Explicit POSTGRES_* credentials (local dev preference)
    explicit_password = (os.getenv("POSTGRES_PASSWORD") or "").strip()
    if explicit_password and explicit_password.upper() != "CHANGE_ME":
        res: dict[str, Any] = {
            "host": (os.getenv("POSTGRES_HOST") or "localhost").strip(),
            "port": _optional_int("POSTGRES_PORT", 5432),
            "database": (os.getenv("POSTGRES_DB") or "iot_security").strip(),
            "user": (os.getenv("POSTGRES_USER") or "postgres").strip(),
            "password": explicit_password,
        }
        sslmode = (os.getenv("POSTGRES_SSLMODE") or os.getenv("PGSSLMODE") or "").strip()
        if sslmode:
            res["sslmode"] = sslmode
        return res

    # 3. Fallback to DATABASE_URL (from .env or remaining configuration)
    if database_url and "CHANGE_ME" not in database_url:
        parsed = _parse_database_url(database_url)
        if not parsed.get("password"):
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
        if os.getenv("POSTGRES_SSLMODE") or os.getenv("PGSSLMODE"):
            parsed["sslmode"] = (os.getenv("POSTGRES_SSLMODE") or os.getenv("PGSSLMODE", "")).strip()
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

    pg_sslmode: str | None = None
    pg_extra_params: dict[str, Any] = field(default_factory=dict)

    @property
    def postgres_conninfo(self) -> str:
        """psycopg connection string (never log this — it contains the password)."""
        params: dict[str, Any] = {
            "host": self.pg_host,
            "port": self.pg_port,
            "dbname": self.pg_database,
            "user": self.pg_user,
        }
        if self.pg_password:
            params["password"] = self.pg_password
        if self.pg_sslmode:
            params["sslmode"] = self.pg_sslmode
        if self.pg_extra_params:
            for k, v in self.pg_extra_params.items():
                if k not in params:
                    params[k] = v
        return make_conninfo(**params)


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
        pg_sslmode=pg.get("sslmode"),
        pg_extra_params=pg.get("extra_params") or {},
    )
