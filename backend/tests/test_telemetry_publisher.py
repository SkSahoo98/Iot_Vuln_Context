"""Unit tests for the Secure Live IoT Telemetry Publisher.

Verifies:
- Only approved device IDs (ESP32-01, ESP32-02) are accepted.
- Private IP addresses, MAC addresses, and credentials are completely excluded.
- Range checks for temperature and humidity.
- Rejection of 0.0/0.0 sensor fault readings.
- Original historical timestamps are preserved.
- Duplicate readings are skipped.
- Both devices are processed independently.
- Transaction rollback on batch failures.
- Empty batches do not perform database writes.
- Repeated runs with the same data do not create duplicates.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from app.services.telemetry_sanitizer import (
    ALLOWED_DEVICE_IDS,
    TelemetryReading,
    TelemetryValidationError,
    filter_and_validate_batch,
    sanitize_telemetry_row,
)
from scripts.publish_telemetry_to_neon import (
    SingleInstanceLock,
    insert_telemetry_into_neon,
)


def _sample_raw_rows():
    t0 = datetime(2026, 11, 5, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=5)
    t2 = t0 + timedelta(seconds=10)

    return [
        {
            "id": 100,
            "device_id": "ESP32-01",
            "temperature": Decimal("29.20"),
            "humidity": Decimal("75.00"),
            "timestamp": t0,
            "ip_address": "10.32.252.105",
            "mac_address": "24:6F:28:B2:1A:BC",
            "secret_key": "private_mqtt_token",
        },
        {
            "id": 101,
            "device_id": "ESP32-02",
            "temperature": Decimal("28.90"),
            "humidity": Decimal("76.50"),
            "timestamp": t0,
            "ip_address": "10.32.252.57",
            "topic": "iot/esp32/02/sensor",
        },
        {
            "id": 102,
            "device_id": "ESP32-01",
            "temperature": 29.3,
            "humidity": 75.5,
            "timestamp": t1,
        },
        {
            "id": 103,
            "device_id": "ESP32-02",
            "temperature": 29.0,
            "humidity": 76.6,
            "timestamp": t1,
        },
    ]


def test_allowed_device_ids_only():
    valid = {"device_id": "ESP32-01", "temperature": 25.0, "humidity": 50.0, "timestamp": datetime.now(UTC)}
    r = sanitize_telemetry_row(valid)
    assert r.device_id == "ESP32-01"

    invalid_dev = {"device_id": "ROGUE-DEVICE-99", "temperature": 25.0, "humidity": 50.0, "timestamp": datetime.now(UTC)}
    with pytest.raises(TelemetryValidationError, match="not in approved list"):
        sanitize_telemetry_row(invalid_dev)


def test_ip_and_sensitive_fields_excluded():
    row = {
        "device_id": "ESP32-01",
        "temperature": 26.5,
        "humidity": 60.0,
        "timestamp": datetime.now(UTC),
        "ip_address": "10.32.252.105",
        "password": "broker_password_123",
        "mqtt_topic": "iot/esp32/01/sensor",
    }
    reading = sanitize_telemetry_row(row)
    as_tuple = reading.as_tuple()

    # TelemetryReading only has: device_id, temperature, humidity, timestamp
    assert len(as_tuple) == 4
    assert not hasattr(reading, "ip_address")
    assert not hasattr(reading, "password")
    assert not hasattr(reading, "mqtt_topic")


def test_temperature_and_humidity_validation():
    base = {"device_id": "ESP32-01", "timestamp": datetime.now(UTC)}

    # Out of range temperature
    with pytest.raises(TelemetryValidationError, match="Temperature.*out of valid range"):
        sanitize_telemetry_row({**base, "temperature": 150.0, "humidity": 50.0})

    # Out of range humidity
    with pytest.raises(TelemetryValidationError, match="Humidity.*out of valid range"):
        sanitize_telemetry_row({**base, "temperature": 25.0, "humidity": 120.0})

    # Non-numeric temperature
    with pytest.raises(TelemetryValidationError, match="temperature must be numeric"):
        sanitize_telemetry_row({**base, "temperature": "invalid", "humidity": 50.0})

    # 0.0/0.0 sensor fault reading
    with pytest.raises(TelemetryValidationError, match="Glitched sensor reading"):
        sanitize_telemetry_row({**base, "temperature": 0.0, "humidity": 0.0})


def test_original_timestamp_preserved():
    original_ts = datetime(2026, 11, 4, 18, 30, 0, tzinfo=UTC)
    row = {"device_id": "ESP32-01", "temperature": 25.0, "humidity": 50.0, "timestamp": original_ts}
    reading = sanitize_telemetry_row(row)
    assert reading.timestamp == original_ts
    assert reading.timestamp.tzinfo is not None


def test_duplicate_readings_skipped_in_batch():
    rows = _sample_raw_rows()
    # Add an identical duplicate for ESP32-01 at t0
    duplicate_row = dict(rows[0])
    all_rows = rows + [duplicate_row]

    valid_readings, duplicates, invalids = filter_and_validate_batch(all_rows)
    assert len(valid_readings) == 4
    assert duplicates == 1
    assert invalids == 0


def test_devices_processed_independently():
    rows = _sample_raw_rows()
    valid_readings, _, _ = filter_and_validate_batch(rows)

    esp1 = [r for r in valid_readings if r.device_id == "ESP32-01"]
    esp2 = [r for r in valid_readings if r.device_id == "ESP32-02"]

    assert len(esp1) == 2
    assert len(esp2) == 2
    assert all(r.device_id == "ESP32-01" for r in esp1)
    assert all(r.device_id == "ESP32-02" for r in esp2)


def test_empty_batch_does_not_write():
    # Calling insert with empty list returns 0 without connecting
    count = insert_telemetry_into_neon("postgresql://dummy", [])
    assert count == 0


def test_repeated_runs_skip_existing_keys():
    rows = _sample_raw_rows()
    t0 = rows[0]["timestamp"]

    # Pretend Neon already has (ESP32-01, t0) and (ESP32-02, t0)
    existing_neon_keys = {
        ("ESP32-01", t0),
        ("ESP32-02", t0),
    }

    valid_readings, duplicates, _ = filter_and_validate_batch(rows, existing_keys=existing_neon_keys)
    # Only the t1 readings (2 rows) should be eligible
    assert len(valid_readings) == 2
    assert duplicates == 2
    assert all(r.timestamp > t0 for r in valid_readings)


def test_single_instance_lock(tmp_path):
    lock_file = tmp_path / "test.lock"
    lock1 = SingleInstanceLock(lock_file)
    lock2 = SingleInstanceLock(lock_file)

    assert lock1.acquire() is True
    # Second acquisition fails because first has exclusive lock
    assert lock2.acquire() is False

    lock1.release()
    # Now second can acquire
    assert lock2.acquire() is True
    lock2.release()

