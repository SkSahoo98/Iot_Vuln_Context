"""Unit tests for MQTT authentication in the collector and firmware configs.

Tests run in-memory without requiring live network or database connections.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from mqtt_collector import collector, config


def _make_dummy_settings(**overrides) -> config.Settings:
    defaults = {
        "pg_host": "localhost",
        "pg_port": 5432,
        "pg_database": "iot_security",
        "pg_user": "postgres",
        "pg_password": "testpassword",
        "mqtt_broker_host": "10.32.252.85",
        "mqtt_broker_port": 1883,
        "mqtt_topic": "iot/esp32/+/sensor",
        "mqtt_client_id": "iot-security-mqtt-collector",
        "mqtt_username": "iot_collector",
        "mqtt_password": "collector_secret_pass",
        "db_pool_min_size": 1,
        "db_pool_max_size": 2,
    }
    defaults.update(overrides)
    return config.Settings(**defaults)


def test_settings_loads_mqtt_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Username and password are correctly loaded from environment."""
    monkeypatch.setenv("POSTGRES_PASSWORD", "testpass")
    monkeypatch.setenv("MQTT_USERNAME", "iot_collector")
    monkeypatch.setenv("MQTT_PASSWORD", "my_secret_token_123")
    monkeypatch.setenv("MQTT_BROKER_HOST", "10.32.252.85")

    settings = config.load_settings()
    assert settings.mqtt_username == "iot_collector"
    assert settings.mqtt_password == "my_secret_token_123"
    assert settings.mqtt_broker_host == "10.32.252.85"


def test_settings_rejects_missing_credentials_when_auth_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing username or password raises clear RuntimeError when auth is required."""
    monkeypatch.setenv("POSTGRES_PASSWORD", "testpass")
    monkeypatch.delenv("MQTT_USERNAME", raising=False)
    monkeypatch.delenv("MQTT_PASSWORD", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        config.load_settings(require_mqtt_auth=True)

    assert "MQTT authentication credentials missing" in str(exc_info.value)
    assert "anonymous access is not permitted" in str(exc_info.value)


def test_collector_setup_configures_authentication_before_connect() -> None:
    """Collector calls username_pw_set on the MQTT client prior to connection."""
    settings = _make_dummy_settings(
        mqtt_username="iot_collector",
        mqtt_password="supersecretpassword",
    )
    col = collector.MqttPostgresCollector(settings)

    with patch("paho.mqtt.client.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        col._setup_mqtt_client()

        # Verify authentication is configured on the MQTT client
        mock_client.username_pw_set.assert_called_once_with(
            username="iot_collector",
            password="supersecretpassword",
        )
        # Verify reconnection delay is configured
        mock_client.reconnect_delay_set.assert_called_once_with(min_delay=1, max_delay=60)


def test_collector_setup_rejects_missing_credentials() -> None:
    """Collector raises a clear error rather than silently falling back to anonymous access."""
    settings_no_user = _make_dummy_settings(mqtt_username=None, mqtt_password="secret")
    col = collector.MqttPostgresCollector(settings_no_user)
    with pytest.raises(RuntimeError, match="MQTT authentication credentials missing"):
        col._setup_mqtt_client()

    settings_no_pass = _make_dummy_settings(mqtt_username="iot_collector", mqtt_password=None)
    col2 = collector.MqttPostgresCollector(settings_no_pass)
    with pytest.raises(RuntimeError, match="MQTT authentication credentials missing"):
        col2._setup_mqtt_client()


def test_password_not_exposed_in_logs_or_repr(caplog: pytest.LogCaptureFixture) -> None:
    """Collector logs username but never prints password."""
    caplog.set_level(logging.INFO)
    settings = _make_dummy_settings(
        mqtt_username="iot_collector",
        mqtt_password="sensitive_cleartext_password_xyz",
    )
    col = collector.MqttPostgresCollector(settings)

    with patch("paho.mqtt.client.Client"):
        col._setup_mqtt_client()

    # Simulate connection log
    mock_client = MagicMock()
    mock_client.subscribe.return_value = (0, 1)
    col._on_connect(mock_client, None, None, 0)

    # Check captured log records
    captured = caplog.text
    assert "iot_collector" in captured
    assert "sensitive_cleartext_password_xyz" not in captured


def test_on_connect_handles_auth_failure_clearly(caplog: pytest.LogCaptureFixture) -> None:
    """Auth failures (rc=4/5 or ReasonCodes) produce clear diagnostic logs without passwords."""
    caplog.set_level(logging.ERROR)
    settings = _make_dummy_settings(
        mqtt_username="iot_collector",
        mqtt_password="sensitive_cleartext_password_xyz",
    )
    col = collector.MqttPostgresCollector(settings)

    mock_client = MagicMock()
    # rc=5 is "Not authorized" in MQTT 3.1.1
    col._on_connect(mock_client, None, None, 5)

    captured = caplog.text
    assert "MQTT authentication failed" in captured
    assert "iot_collector" in captured
    assert "sensitive_cleartext_password_xyz" not in captured


def test_topic_subscription_preserved() -> None:
    """Collector subscription topic remains iot/esp32/+/sensor."""
    settings = _make_dummy_settings()
    assert settings.mqtt_topic == "iot/esp32/+/sensor"

    col = collector.MqttPostgresCollector(settings)
    mock_client = MagicMock()
    mock_client.subscribe.return_value = (0, 1)

    col._on_connect(mock_client, None, None, 0)
    mock_client.subscribe.assert_called_once_with("iot/esp32/+/sensor", qos=1)


def test_telemetry_processing_preserved() -> None:
    """Payload validation and parsing logic remains intact."""
    col = collector.MqttPostgresCollector(_make_dummy_settings())
    valid_payload = {
        "device_id": "ESP32-01",
        "ip_address": "10.32.252.105",
        "temperature": 27.50,
        "humidity": 60.10,
    }
    reading = col._validate_payload(valid_payload)
    assert reading.device_id == "ESP32-01"
    assert reading.ip_address == "10.32.252.105"
    assert reading.temperature == Decimal("27.50")
    assert reading.humidity == Decimal("60.10")


def test_firmware_files_contain_correct_auth_config() -> None:
    """ESP32 firmware files must have proper auth configuration and no hardcoded passwords."""
    project_root = Path(__file__).resolve().parents[2]

    # ESP32-01 firmware check
    ino1 = (project_root / "firmware" / "esp32_device_01" / "esp32_device_01.ino").read_text(
        encoding="utf-8"
    )
    assert 'DEVICE_ID "ESP32-01"' in ino1
    assert 'MQTT_TOPIC "iot/esp32/01/sensor"' in ino1
    assert "mqtt.connect(DEVICE_ID, MQTT_USERNAME, MQTT_PASSWORD)" in ino1
    assert "MQTT_PASSWORD missing in secrets.h" in ino1
    # Ensure password is not printed to Serial
    assert "Serial.print(MQTT_PASSWORD)" not in ino1
    assert "Serial.println(MQTT_PASSWORD)" not in ino1

    # ESP32-02 firmware check
    ino2 = (project_root / "firmware" / "esp32_device_02" / "esp32_device_02.ino").read_text(
        encoding="utf-8"
    )
    assert 'DEVICE_ID "ESP32-02"' in ino2
    assert 'MQTT_TOPIC "iot/esp32/02/sensor"' in ino2
    assert "mqtt.connect(DEVICE_ID, MQTT_USERNAME, MQTT_PASSWORD)" in ino2
    assert "MQTT_PASSWORD missing in secrets.h" in ino2
    # Ensure password is not printed to Serial
    assert "Serial.print(MQTT_PASSWORD)" not in ino2
    assert "Serial.println(MQTT_PASSWORD)" not in ino2

    # Secrets example checks
    ex1 = (
        project_root / "firmware" / "esp32_device_01" / "secrets.h.example"
    ).read_text(encoding="utf-8")
    assert 'MQTT_USERNAME = "esp32_01"' in ex1
    assert "REPLACE_LOCALLY" in ex1

    ex2 = (
        project_root / "firmware" / "esp32_device_02" / "secrets.h.example"
    ).read_text(encoding="utf-8")
    assert 'MQTT_USERNAME = "esp32_02"' in ex2
    assert "REPLACE_LOCALLY" in ex2

    # .gitignore check
    gitignore = (project_root / ".gitignore").read_text(encoding="utf-8")
    assert "secrets.h" in gitignore
    assert "**/secrets.h" in gitignore
    assert ".env" in gitignore
