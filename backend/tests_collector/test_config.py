"""Configuration-only tests; no database or MQTT connection is performed."""

from __future__ import annotations

from pathlib import Path

import pytest

from mqtt_collector import config


def _write_env(directory: Path, host: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / ".env").write_text(
        f"MQTT_BROKER_HOST={host}\nMQTT_BROKER_PORT=1883\n",
        encoding="utf-8",
    )


def test_backend_env_precedes_project_root_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    backend = tmp_path / "backend"
    project = tmp_path / "project"
    _write_env(project, "10.84.237.85")
    _write_env(backend, "10.188.244.85")

    monkeypatch.setattr(config, "BACKEND_ROOT", backend)
    monkeypatch.setattr(config, "PROJECT_ROOT", project)
    monkeypatch.delenv("MQTT_BROKER_HOST", raising=False)
    monkeypatch.delenv("MQTT_BROKER_PORT", raising=False)

    config.load_environment_files()
    settings = config.load_settings()

    assert settings.mqtt_broker_host == "10.188.244.85"
    assert settings.mqtt_broker_port == 1883


def test_explicit_process_environment_keeps_highest_precedence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    backend = tmp_path / "backend"
    project = tmp_path / "project"
    _write_env(project, "10.84.237.85")
    _write_env(backend, "10.188.244.85")

    monkeypatch.setattr(config, "BACKEND_ROOT", backend)
    monkeypatch.setattr(config, "PROJECT_ROOT", project)
    monkeypatch.setenv("MQTT_BROKER_HOST", "10.0.0.99")
    monkeypatch.setenv("MQTT_BROKER_PORT", "1884")

    config.load_environment_files()
    settings = config.load_settings()

    assert settings.mqtt_broker_host == "10.0.0.99"
    assert settings.mqtt_broker_port == 1884


def test_local_database_fallback_preserved(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """When no process-level override is set, local PostgreSQL configuration is preserved."""
    project = tmp_path / "project"
    project.mkdir(parents=True, exist_ok=True)
    (project / ".env").write_text(
        "DATABASE_URL=postgresql+psycopg://local_user:local_pass@localhost:5432/iot_security\n"
        "MQTT_BROKER_HOST=10.32.252.85\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(config, "BACKEND_ROOT", tmp_path / "backend")
    monkeypatch.setattr(config, "PROJECT_ROOT", project)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)

    config.load_environment_files()
    settings = config.load_settings()

    assert settings.pg_host == "localhost"
    assert settings.pg_port == 5432
    assert settings.pg_database == "iot_security"
    assert settings.pg_user == "local_user"
    assert settings.pg_password == "local_pass"
    assert settings.pg_sslmode is None
    assert "host=localhost" in settings.postgres_conninfo
    assert "dbname=iot_security" in settings.postgres_conninfo
    assert "sslmode" not in settings.postgres_conninfo


def test_neon_url_preserves_ssl_settings(monkeypatch) -> None:
    """Neon PostgreSQL connection strings preserve sslmode=require in settings and conninfo."""
    fake_neon = (
        "postgresql://neon_user:fake_secret_token@"
        "ep-cool-project-12345.us-east-2.aws.neon.tech:5432/neondb?sslmode=require"
    )
    monkeypatch.setenv("DATABASE_URL", fake_neon)

    config.load_environment_files()
    settings = config.load_settings()

    assert settings.pg_host == "ep-cool-project-12345.us-east-2.aws.neon.tech"
    assert settings.pg_port == 5432
    assert settings.pg_database == "neondb"
    assert settings.pg_user == "neon_user"
    assert settings.pg_password == "fake_secret_token"
    assert settings.pg_sslmode == "require"
    assert "sslmode=require" in settings.postgres_conninfo
    assert "host=ep-cool-project-12345.us-east-2.aws.neon.tech" in settings.postgres_conninfo


def test_query_parameters_not_silently_discarded(monkeypatch) -> None:
    """Extra connection parameters like timeout and app name are preserved."""
    url = (
        "postgresql://test_user:test_secret@fake-pg.internal:5433/custom_db?"
        "sslmode=verify-full&connect_timeout=15&application_name=mqtt_collector"
    )
    monkeypatch.setenv("DATABASE_URL", url)

    config.load_environment_files()
    settings = config.load_settings()

    assert settings.pg_port == 5433
    assert settings.pg_sslmode == "verify-full"
    assert settings.pg_extra_params == {
        "connect_timeout": "15",
        "application_name": "mqtt_collector",
    }
    assert "sslmode=verify-full" in settings.postgres_conninfo
    assert "connect_timeout=15" in settings.postgres_conninfo
    assert "application_name=mqtt_collector" in settings.postgres_conninfo


def test_process_environment_overrides_env_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Process-level DATABASE_URL takes absolute precedence over local .env configurations."""
    backend = tmp_path / "backend"
    backend.mkdir(parents=True, exist_ok=True)
    # Write local environment variables that must be ignored
    (backend / ".env").write_text(
        "POSTGRES_HOST=127.0.0.1\n"
        "POSTGRES_PORT=5433\n"
        "POSTGRES_DB=local_db\n"
        "POSTGRES_USER=local_admin\n"
        "POSTGRES_PASSWORD=local_secret_pass\n"
        "DATABASE_URL=postgresql://local_admin:local_secret_pass@127.0.0.1:5433/local_db\n",
        encoding="utf-8",
    )

    cloud_url = (
        "postgresql://cloud_user:cloud_pass@"
        "ep-cloud.aws.neon.tech:5432/cloud_db?sslmode=require"
    )
    monkeypatch.setattr(config, "BACKEND_ROOT", backend)
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path / "project")
    monkeypatch.setenv("DATABASE_URL", cloud_url)

    config.load_environment_files()
    settings = config.load_settings()

    assert settings.pg_host == "ep-cloud.aws.neon.tech"
    assert settings.pg_port == 5432
    assert settings.pg_database == "cloud_db"
    assert settings.pg_user == "cloud_user"
    assert settings.pg_password == "cloud_pass"
    assert settings.pg_sslmode == "require"
    assert "host=ep-cloud.aws.neon.tech" in settings.postgres_conninfo
    assert "sslmode=require" in settings.postgres_conninfo


def test_credentials_not_printed_in_error_messages(monkeypatch) -> None:
    """Sensitive passwords and tokens must never appear in parser error messages."""
    invalid_urls = [
        "mysql://user_admin:SUPER_SECRET_TOKEN_DO_NOT_LEAK@invalid-host/dbname",
        "postgresql://user_admin:SUPER_SECRET_TOKEN_DO_NOT_LEAK@invalid-host/",
        "postgresql://user_admin:SUPER_SECRET_TOKEN_DO_NOT_LEAK@invalid-host/dbname?===invalid",
    ]
    for url in invalid_urls:
        monkeypatch.setenv("DATABASE_URL", url)
        with pytest.raises(RuntimeError) as exc_info:
            config.load_settings()

        error_msg = str(exc_info.value)
        assert "SUPER_SECRET_TOKEN_DO_NOT_LEAK" not in error_msg
        assert "user_admin" not in error_msg


def test_missing_password_error_does_not_print_secret(monkeypatch) -> None:
    """Missing password error identifies the issue safely without leaking other config."""
    no_pass_url = "postgresql://my_test_user@localhost:5432/testdb"
    monkeypatch.setenv("DATABASE_URL", no_pass_url)

    with pytest.raises(RuntimeError) as exc_info:
        config.load_settings()

    assert "has no password" in str(exc_info.value)
