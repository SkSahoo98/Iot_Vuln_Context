"""Configuration-only tests; no database or MQTT connection is performed."""

from __future__ import annotations

from pathlib import Path

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
