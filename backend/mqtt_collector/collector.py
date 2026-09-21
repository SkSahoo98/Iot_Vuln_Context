"""
MQTT → PostgreSQL collector for ESP32 DHT22 sensor readings.

Subscribes to iot/esp32/+/sensor, validates JSON payloads, and writes
append-only rows into sensor_data while marking devices ONLINE.

Run from the backend directory:

    python -m mqtt_collector.collector
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address
from typing import Any

import paho.mqtt.client as mqtt
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from mqtt_collector.config import Settings, load_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mqtt_collector")

# How long to wait for the first successful MQTT CONNACK before failing startup.
MQTT_CONNECT_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class SensorReading:
    device_id: str
    temperature: Decimal
    humidity: Decimal
    ip_address: str | None = None


class ValidationError(Exception):
    """Raised when an MQTT payload fails validation (stage D)."""


class UnknownDeviceError(Exception):
    """Raised when device_id is not registered in devices (stage E)."""


class MqttPostgresCollector:
    """Long-running service that bridges Mosquitto MQTT to PostgreSQL."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._pool: ConnectionPool | None = None
        self._client: mqtt.Client | None = None
        self._stopping = False
        self._ever_connected = False
        self._connected_event = threading.Event()
        self._shutdown_lock = threading.Lock()

    def request_shutdown(self) -> None:
        """Ask the main loop to stop (safe to call from signal handlers)."""
        self._stopping = True

    # ------------------------------------------------------------------ setup
    def start(self) -> None:
        self._open_database_pool()
        self._setup_mqtt_client()
        self._connect_mqtt_with_timeout()

        try:
            while not self._stopping:
                time.sleep(0.5)
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._client is None and self._pool is None:
                return

            self._stopping = True
            logger.info("Shutting down MQTT collector ...")

            if self._client is not None:
                try:
                    self._client.loop_stop()
                except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                    logger.warning("MQTT loop_stop warning: %s", exc)
                try:
                    self._client.disconnect()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("MQTT disconnect warning: %s", exc)
                self._client = None

            if self._pool is not None:
                try:
                    self._pool.close()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Database pool close warning: %s", exc)
                self._pool = None

            logger.info("Shutdown completed")

    def _open_database_pool(self) -> None:
        logger.info(
            "Opening PostgreSQL pool (host=%s db=%s user=%s)",
            self.settings.pg_host,
            self.settings.pg_database,
            self.settings.pg_user,
        )
        try:
            self._pool = ConnectionPool(
                conninfo=self.settings.postgres_conninfo,
                min_size=self.settings.db_pool_min_size,
                max_size=self.settings.db_pool_max_size,
                kwargs={"row_factory": dict_row},
                open=True,
            )
            self._verify_database()
        except Exception as exc:
            logger.error("PostgreSQL unavailable: %s", exc)
            raise RuntimeError(f"PostgreSQL unavailable: {exc}") from exc

        logger.info("PostgreSQL pool ready")

    def _setup_mqtt_client(self) -> None:
        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.settings.mqtt_client_id,
            protocol=mqtt.MQTTv311,
        )
        # Automatic reconnect after a previously successful connection.
        self._client.reconnect_delay_set(min_delay=1, max_delay=60)
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_subscribe = self._on_subscribe
        self._client.on_message = self._on_message

        if self.settings.mqtt_username:
            self._client.username_pw_set(
                self.settings.mqtt_username,
                self.settings.mqtt_password,
            )

    def _connect_mqtt_with_timeout(self) -> None:
        """Fail startup clearly if the broker does not accept the first connection."""
        assert self._client is not None
        self._connected_event.clear()

        logger.info(
            "Connecting to MQTT broker %s:%s",
            self.settings.mqtt_broker_host,
            self.settings.mqtt_broker_port,
        )
        logger.info("Attempting MQTT connection ...")

        try:
            # Synchronous first connect: fails immediately if host/port unreachable.
            self._client.connect(
                self.settings.mqtt_broker_host,
                self.settings.mqtt_broker_port,
                keepalive=60,
            )
        except Exception as exc:
            logger.error("MQTT broker unavailable: %s", exc)
            raise RuntimeError(f"MQTT broker unavailable: {exc}") from exc

        self._client.loop_start()

        if not self._connected_event.wait(timeout=MQTT_CONNECT_TIMEOUT_SECONDS):
            message = (
                f"MQTT broker unavailable: no CONNACK within "
                f"{MQTT_CONNECT_TIMEOUT_SECONDS}s "
                f"({self.settings.mqtt_broker_host}:"
                f"{self.settings.mqtt_broker_port})"
            )
            logger.error(message)
            raise RuntimeError(message)

    # ----------------------------------------------------------- MQTT callbacks
    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        rc_value = getattr(reason_code, "value", reason_code)
        if rc_value != 0:
            logger.error("Failed MQTT connection (reason=%s)", reason_code)
            return

        if self._ever_connected:
            logger.info("MQTT reconnected successfully")
        else:
            logger.info("MQTT connected")

        self._ever_connected = True
        self._connected_event.set()

        result, mid = client.subscribe(self.settings.mqtt_topic, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            logger.error(
                "MQTT connected but subscription failed "
                "(topic=%s result=%s)",
                self.settings.mqtt_topic,
                result,
            )
            return

        logger.info(
            "Subscription requested for topic: %s (mid=%s)",
            self.settings.mqtt_topic,
            mid,
        )

    def _on_subscribe(
        self,
        client: mqtt.Client,
        userdata: Any,
        mid: int,
        reason_codes: Any,
        properties: Any = None,
    ) -> None:
        # reason_codes may be a list of ReasonCode (v2) or a list of ints.
        codes = reason_codes if isinstance(reason_codes, (list, tuple)) else [reason_codes]
        failed = False
        for code in codes:
            value = getattr(code, "value", code)
            # MQTT 3.1.1: 0x00–0x02 are success QoS grants; >= 0x80 is failure.
            if isinstance(value, int) and value >= 128:
                failed = True

        if failed:
            logger.error(
                "MQTT connected but subscription failed "
                "(topic=%s mid=%s reason_codes=%s)",
                self.settings.mqtt_topic,
                mid,
                reason_codes,
            )
            return

        logger.info("Subscribed to topic: %s", self.settings.mqtt_topic)

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        if self._stopping:
            logger.info("MQTT disconnected (shutdown)")
            return

        logger.warning(
            "MQTT disconnected (reason=%s). Automatic reconnect in progress ...",
            reason_code,
        )

    def _on_message(
        self,
        client: mqtt.Client,
        userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        logger.info("Message received")
        logger.info("Topic: %s", msg.topic)

        try:
            try:
                payload_text = msg.payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                logger.warning(
                    "Invalid message ignored: payload is not valid UTF-8 (%s)",
                    exc,
                )
                return

            try:
                data = json.loads(payload_text)
            except json.JSONDecodeError as exc:
                logger.warning("Invalid message ignored: invalid JSON (%s)", exc)
                return

            reading = self._validate_payload(data)
            self._persist_reading(reading)

            logger.info("Device: %s", reading.device_id)
            logger.info("Temperature: %s C", reading.temperature)
            logger.info("Humidity: %s %%", reading.humidity)
            if reading.ip_address:
                logger.info("Reported IP: %s", reading.ip_address)
            logger.info("Database insert successful")

        except ValidationError as exc:
            message = str(exc)
            if message.startswith("Invalid sensor reading ignored:"):
                logger.warning("%s", message)
            else:
                logger.warning("Invalid message ignored: %s", exc)
        except UnknownDeviceError as exc:
            logger.warning("Device not found: %s", exc)
        except psycopg.Error as exc:
            logger.error("Database insert failed: %s", exc)
        except Exception as exc:  # noqa: BLE001 — keep the collector alive
            logger.exception("Unexpected error while processing message: %s", exc)

    # ----------------------------------------------------------- validation/db
    def _validate_payload(self, data: Any) -> SensorReading:
        if not isinstance(data, dict):
            raise ValidationError("payload must be a JSON object")

        if "device_id" not in data:
            raise ValidationError("device_id is missing")

        device_id = data.get("device_id")
        if not isinstance(device_id, str) or not device_id.strip():
            raise ValidationError("device_id must be a non-empty string")
        device_id = device_id.strip()

        temperature = self._to_decimal(data.get("temperature"), "temperature")
        humidity = self._to_decimal(data.get("humidity"), "humidity")

        if humidity < 0 or humidity > 100:
            raise ValidationError("humidity must be between 0 and 100")

        # Transient DHT22 failures often report exactly 0.0/0.0 — ignore them so
        # they never become "latest" telemetry or refresh ONLINE freshness.
        if temperature == 0 and humidity == 0:
            raise ValidationError(
                f"Invalid sensor reading ignored: {device_id} "
                f"temperature={temperature} humidity={humidity}"
            )

        # Optional device-reported Wi-Fi IP. Invalid values are ignored so
        # temperature/humidity telemetry still persists.
        reported_ip = self._parse_optional_ip(data.get("ip_address"))

        return SensorReading(
            device_id=device_id,
            temperature=temperature,
            humidity=humidity,
            ip_address=reported_ip,
        )

    @staticmethod
    def _parse_optional_ip(value: Any) -> str | None:
        """Return a canonical IP string, or None if missing/invalid."""
        if value is None:
            return None
        if not isinstance(value, str):
            logger.warning("Invalid ip_address ignored: value must be a string")
            return None
        cleaned = value.strip()
        if cleaned == "":
            return None
        try:
            return str(ip_address(cleaned))
        except ValueError:
            logger.warning("Invalid ip_address ignored: %r", cleaned)
            return None

    @staticmethod
    def _to_decimal(value: Any, field_name: str) -> Decimal:
        if isinstance(value, bool) or value is None:
            raise ValidationError(f"{field_name} must be numeric")
        try:
            return Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise ValidationError(f"{field_name} must be numeric") from exc

    def _verify_database(self) -> None:
        assert self._pool is not None
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 AS ok")
                row = cur.fetchone()
                if not row or row["ok"] != 1:
                    raise RuntimeError("PostgreSQL connectivity check failed")

    def _persist_reading(self, reading: SensorReading) -> None:
        assert self._pool is not None
        observed_at = datetime.now(UTC)

        with self._pool.connection() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 AS present FROM devices WHERE device_id = %s",
                        (reading.device_id,),
                    )
                    if cur.fetchone() is None:
                        raise UnknownDeviceError(
                            f"'{reading.device_id}' is not registered in devices"
                        )

                    cur.execute(
                        """
                        INSERT INTO sensor_data (device_id, temperature, humidity, timestamp)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            reading.device_id,
                            reading.temperature,
                            reading.humidity,
                            observed_at,
                        ),
                    )

                    # Always mark ONLINE. Update ip_address only when the ESP32
                    # reported a validated IP (never overwrite with NULL).
                    if reading.ip_address is not None:
                        cur.execute(
                            """
                            UPDATE devices
                            SET status = 'ONLINE',
                                ip_address = %s::inet,
                                updated_at = NOW()
                            WHERE device_id = %s
                            """,
                            (reading.ip_address, reading.device_id),
                        )
                    else:
                        cur.execute(
                            """
                            UPDATE devices
                            SET status = 'ONLINE',
                                updated_at = NOW()
                            WHERE device_id = %s
                            """,
                            (reading.device_id,),
                        )


def main() -> int:
    logger.info("Starting MQTT → PostgreSQL collector")

    try:
        settings = load_settings()
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1

    logger.info(
        "Config: broker=%s:%s topic=%s db=%s@%s/%s",
        settings.mqtt_broker_host,
        settings.mqtt_broker_port,
        settings.mqtt_topic,
        settings.pg_user,
        settings.pg_host,
        settings.pg_database,
    )

    collector = MqttPostgresCollector(settings)

    def _handle_signal(signum: int, frame: Any) -> None:  # noqa: ARG001
        logger.info("Received signal %s — requesting shutdown", signum)
        collector.request_shutdown()

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    try:
        collector.start()
    except KeyboardInterrupt:
        collector.request_shutdown()
        collector.shutdown()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Collector stopped due to startup/runtime error: %s", exc)
        collector.shutdown()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
