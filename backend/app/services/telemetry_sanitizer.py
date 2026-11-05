"""Sanitizer and validation engine for IoT device telemetry.

Ensures that only approved sensor readings (device_id, temperature, humidity, timestamp)
are transferred from local PostgreSQL to Neon PostgreSQL.

Guarantees:
- Rejection of unapproved device IDs.
- Complete exclusion of IP addresses, MAC addresses, credentials, and raw messages.
- Numeric range validation for DHT22 temperature and humidity.
- Rejection of 0.0/0.0 sensor fault readings.
- Preservation of original historical timestamps.
- In-memory duplicate filtering.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

ALLOWED_DEVICE_IDS = frozenset({"ESP32-01", "ESP32-02"})

# Valid operating ranges for DHT22 sensors
MIN_TEMPERATURE = -40.0
MAX_TEMPERATURE = 80.0
MIN_HUMIDITY = 0.0
MAX_HUMIDITY = 100.0


class TelemetryValidationError(ValueError):
    """Raised when a telemetry record fails validation rules."""


@dataclass(frozen=True)
class TelemetryReading:
    """Sanitized, strictly-typed telemetry reading ready for cloud publishing."""

    device_id: str
    temperature: float
    humidity: float
    timestamp: datetime

    def as_tuple(self) -> tuple[str, float, float, datetime]:
        return (self.device_id, self.temperature, self.humidity, self.timestamp)


def _to_float(value: Any, field_name: str) -> float:
    if value is None or isinstance(value, bool):
        raise TelemetryValidationError(f"{field_name} must be numeric (got {value!r})")
    try:
        return float(Decimal(str(value)))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise TelemetryValidationError(f"{field_name} must be numeric (got {value!r})") from exc


def sanitize_telemetry_row(row: dict[str, Any]) -> TelemetryReading:
    """Sanitize and validate a single telemetry record.

    Only extracts device_id, temperature, humidity, and timestamp.
    Any other fields (ip_address, credentials, topics, etc.) are ignored and discarded.
    """
    raw_device_id = row.get("device_id")
    if not isinstance(raw_device_id, str):
        raise TelemetryValidationError(f"Invalid device_id type: {raw_device_id!r}")

    device_id = raw_device_id.strip()
    if device_id not in ALLOWED_DEVICE_IDS:
        raise TelemetryValidationError(f"Device '{device_id}' is not in approved list: {sorted(ALLOWED_DEVICE_IDS)}")

    temp = _to_float(row.get("temperature"), "temperature")
    hum = _to_float(row.get("humidity"), "humidity")

    # Reject 0.0/0.0 glitch readings common on DHT22 line hiccups
    if temp == 0.0 and hum == 0.0:
        raise TelemetryValidationError(f"Glitched sensor reading (0.0/0.0) rejected for {device_id}")

    if not (MIN_TEMPERATURE <= temp <= MAX_TEMPERATURE):
        raise TelemetryValidationError(
            f"Temperature {temp} out of valid range [{MIN_TEMPERATURE}, {MAX_TEMPERATURE}]"
        )

    if not (MIN_HUMIDITY <= hum <= MAX_HUMIDITY):
        raise TelemetryValidationError(
            f"Humidity {hum} out of valid range [{MIN_HUMIDITY}, {MAX_HUMIDITY}]"
        )

    raw_ts = row.get("timestamp")
    if not isinstance(raw_ts, datetime):
        raise TelemetryValidationError(f"Invalid timestamp type: {raw_ts!r}")

    # Ensure UTC-aware timestamp preserving original point in time
    if raw_ts.tzinfo is None:
        ts = raw_ts.replace(tzinfo=UTC)
    else:
        ts = raw_ts.astimezone(UTC)

    return TelemetryReading(
        device_id=device_id,
        temperature=round(temp, 2),
        humidity=round(hum, 2),
        timestamp=ts,
    )


def filter_and_validate_batch(
    raw_rows: list[dict[str, Any]],
    existing_keys: set[tuple[str, datetime]] | None = None,
) -> tuple[list[TelemetryReading], int, int]:
    """Filter and validate a batch of telemetry records.

    Returns:
        (valid_readings, duplicate_count, invalid_count)
    """
    seen_keys: set[tuple[str, datetime]] = set(existing_keys) if existing_keys else set()
    valid_readings: list[TelemetryReading] = []
    duplicate_count = 0
    invalid_count = 0

    for row in raw_rows:
        try:
            reading = sanitize_telemetry_row(row)
        except TelemetryValidationError:
            invalid_count += 1
            continue

        key = (reading.device_id, reading.timestamp)
        if key in seen_keys:
            duplicate_count += 1
            continue

        seen_keys.add(key)
        valid_readings.append(reading)

    return valid_readings, duplicate_count, invalid_count

