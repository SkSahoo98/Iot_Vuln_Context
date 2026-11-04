"""Device inventory service against the live lab schema (BIGSERIAL devices)."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import ip_address

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.schemas.api import DeviceOut, DeviceTelemetryOut
from scanner.targets import parse_allowed_targets


def list_devices(db: Session) -> list[DeviceOut]:
    """Return registered IoT devices with latest *valid* sensor_data telemetry.

    Status is derived from telemetry freshness (not only the stored status column):
    - ONLINE  — latest valid reading within DEVICE_OFFLINE_AFTER_SECONDS
    - OFFLINE — latest valid reading is older than that window
    - UNKNOWN — no valid telemetry has ever been recorded
    """
    settings = get_settings()
    offline_after = max(1, int(settings.device_offline_after_seconds))
    now = datetime.now(UTC)

    try:
        allowed = parse_allowed_targets(settings.assessment_allowed_targets)
    except Exception:
        allowed = frozenset()

    rows = db.execute(
        text(
            """
            SELECT
                d.id,
                d.device_id,
                host(d.ip_address) AS ip_address,
                d.mac_address::text AS mac_address,
                d.device_type,
                d.firmware_version,
                d.status AS stored_status,
                d.created_at,
                d.updated_at,
                s.temperature AS telemetry_temperature,
                s.humidity AS telemetry_humidity,
                s.timestamp AS telemetry_timestamp
            FROM devices d
            LEFT JOIN LATERAL (
                SELECT temperature, humidity, timestamp
                FROM sensor_data
                WHERE device_id = d.device_id
                  AND NOT (temperature = 0 AND humidity = 0)
                ORDER BY timestamp DESC
                LIMIT 1
            ) s ON TRUE
            ORDER BY d.device_id
            """
        )
    ).mappings().all()

    devices: list[DeviceOut] = []
    for row in rows:
        payload = dict(row)
        payload.pop("stored_status", None)
        temperature = payload.pop("telemetry_temperature", None)
        humidity = payload.pop("telemetry_humidity", None)
        timestamp = payload.pop("telemetry_timestamp", None)

        latest_telemetry: DeviceTelemetryOut | None = None
        if temperature is not None and humidity is not None and timestamp is not None:
            latest_telemetry = DeviceTelemetryOut(
                temperature=_as_float(temperature),
                humidity=_as_float(humidity),
                timestamp=timestamp,
            )

        payload["status"] = _derive_status(timestamp, now, offline_after)

        raw_ip = payload.get("ip_address")
        is_auth = False
        if raw_ip:
            try:
                is_auth = ip_address(str(raw_ip).strip()) in allowed
            except ValueError:
                is_auth = False
        payload["is_authorized"] = is_auth

        devices.append(
            DeviceOut.model_validate(
                {
                    **payload,
                    "latest_telemetry": latest_telemetry,
                }
            )
        )
    return devices


def _derive_status(
    telemetry_timestamp: datetime | None,
    now: datetime,
    offline_after_seconds: int,
) -> str:
    if telemetry_timestamp is None:
        return "UNKNOWN"

    ts = telemetry_timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    else:
        ts = ts.astimezone(UTC)

    age_seconds = (now - ts).total_seconds()
    if age_seconds <= offline_after_seconds:
        return "ONLINE"
    return "OFFLINE"


def _as_float(value: float | Decimal) -> float:
    return float(value)
