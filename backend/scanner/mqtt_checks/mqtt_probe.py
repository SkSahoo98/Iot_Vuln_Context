"""Safe MQTT CONNECT probe for an explicitly allowlisted broker."""

from __future__ import annotations

import threading
import uuid
from typing import Any

import paho.mqtt.client as mqtt

from scanner.core.models import Evidence


def probe_mqtt_anonymous(
    target: str,
    port: int = 1883,
    timeout: float = 5.0,
) -> Evidence:
    """Attempt one MQTT 3.1.1 connection without credentials.

    If accepted, subscribe read-only to $SYS/broker/version for at most the
    supplied timeout. The probe never publishes and disconnects immediately.
    """
    connected = threading.Event()
    version_received = threading.Event()
    state: dict[str, Any] = {
        "connection_accepted": False,
        "reason_code": None,
        "reason_text": None,
        "broker_version": None,
        "sys_topic_checked": False,
    }
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"iot-security-probe-{uuid.uuid4().hex[:12]}",
        protocol=mqtt.MQTTv311,
    )

    def on_connect(
        active_client: mqtt.Client,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        value = getattr(reason_code, "value", reason_code)
        state["reason_code"] = int(value) if isinstance(value, int) else None
        state["reason_text"] = str(reason_code)
        state["connection_accepted"] = value == 0
        connected.set()
        if value == 0:
            result, _ = active_client.subscribe("$SYS/broker/version", qos=0)
            state["sys_topic_checked"] = result == mqtt.MQTT_ERR_SUCCESS

    def on_message(
        active_client: mqtt.Client,
        userdata: Any,
        message: mqtt.MQTTMessage,
    ) -> None:
        if message.topic != "$SYS/broker/version":
            return
        try:
            state["broker_version"] = message.payload.decode(
                "utf-8",
                errors="strict",
            )[:200]
        except UnicodeDecodeError:
            state["broker_version_decode_error"] = True
        version_received.set()

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(target, port, keepalive=max(5, int(timeout * 2)))
        client.loop_start()
        if not connected.wait(timeout):
            return Evidence(
                target=target,
                port=port,
                check_type="MQTT_ANONYMOUS_CONNECT",
                result="TIMEOUT",
                evidence_source="MQTT_PROBE",
                observation={
                    **state,
                    "error": "No MQTT CONNACK received before timeout",
                },
            )
        if state["connection_accepted"] and state["sys_topic_checked"]:
            version_received.wait(min(timeout, 2.0))
        result = "ACCEPTED" if state["connection_accepted"] else "REJECTED"
        return Evidence(
            target=target,
            port=port,
            check_type="MQTT_ANONYMOUS_CONNECT",
            result=result,
            evidence_source="MQTT_PROBE",
            observation=state,
        )
    except ConnectionRefusedError as exc:
        return Evidence(
            target=target,
            port=port,
            check_type="MQTT_ANONYMOUS_CONNECT",
            result="REFUSED",
            evidence_source="MQTT_PROBE",
            observation={"error_type": type(exc).__name__},
        )
    except TimeoutError as exc:
        return Evidence(
            target=target,
            port=port,
            check_type="MQTT_ANONYMOUS_CONNECT",
            result="TIMEOUT",
            evidence_source="MQTT_PROBE",
            observation={"error_type": type(exc).__name__},
        )
    except OSError as exc:
        return Evidence(
            target=target,
            port=port,
            check_type="MQTT_ANONYMOUS_CONNECT",
            result="UNREACHABLE",
            evidence_source="MQTT_PROBE",
            observation={
                "error_type": type(exc).__name__,
                "error": str(exc)[:300],
            },
        )
    except Exception as exc:  # malformed broker packets surface from paho here
        return Evidence(
            target=target,
            port=port,
            check_type="MQTT_ANONYMOUS_CONNECT",
            result="PROTOCOL_ERROR",
            evidence_source="MQTT_PROBE",
            observation={
                "error_type": type(exc).__name__,
                "error": str(exc)[:300],
            },
        )
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        try:
            client.loop_stop()
        except Exception:
            pass
