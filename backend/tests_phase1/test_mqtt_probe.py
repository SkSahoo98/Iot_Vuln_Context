from __future__ import annotations

import pytest

import scanner.mqtt_checks.mqtt_probe as mqtt_probe


class Reason:
    def __init__(self, value: int) -> None:
        self.value = value

    def __str__(self) -> str:
        return "Success" if self.value == 0 else "Not authorized"


class Message:
    topic = "$SYS/broker/version"
    payload = b"ObservedBroker/1.0"


class FakeClient:
    def __init__(self, mode: str, **kwargs) -> None:
        self.mode = mode
        self.on_connect = None
        self.on_message = None

    def connect(self, target: str, port: int, keepalive: int) -> None:
        if self.mode == "refused":
            raise ConnectionRefusedError("refused")
        if self.mode == "malformed":
            raise RuntimeError("malformed MQTT response")

    def loop_start(self) -> None:
        code = 0 if self.mode == "accepted" else 5
        self.on_connect(self, None, None, Reason(code), None)

    def subscribe(self, topic: str, qos: int):
        if self.on_message:
            self.on_message(self, None, Message())
        return mqtt_probe.mqtt.MQTT_ERR_SUCCESS, 1

    def disconnect(self) -> None:
        return None

    def loop_stop(self) -> None:
        return None


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("accepted", "ACCEPTED"),
        ("rejected", "REJECTED"),
        ("refused", "REFUSED"),
        ("malformed", "PROTOCOL_ERROR"),
    ],
)
def test_mqtt_probe_reports_observed_outcome(
    monkeypatch,
    mode: str,
    expected: str,
) -> None:
    monkeypatch.setattr(
        mqtt_probe.mqtt,
        "Client",
        lambda **kwargs: FakeClient(mode, **kwargs),
    )
    evidence = mqtt_probe.probe_mqtt_anonymous(
        "10.84.237.85",
        1883,
        timeout=0.01,
    )
    assert evidence.result == expected
    assert evidence.evidence_source == "MQTT_PROBE"
    if mode == "accepted":
        assert evidence.observation["reason_code"] == 0
        assert evidence.observation["broker_version"] == "ObservedBroker/1.0"
