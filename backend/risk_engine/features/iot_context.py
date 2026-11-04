"""
IoT-specific context features used by the dynamic risk engine.

The purpose of this module is to represent security-relevant IoT context
separately from the vulnerability's base severity.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class IoTContext:
    """
    Context associated with an IoT asset.

    Values are intentionally explicit so that the risk calculation can
    be explained and reproduced.
    """

    device_criticality: float
    network_exposure: float
    authentication_security: float
    protocol_security: float
    firmware_security: float

    def __post_init__(self) -> None:
        values = {
            "device_criticality": self.device_criticality,
            "network_exposure": self.network_exposure,
            "authentication_security": self.authentication_security,
            "protocol_security": self.protocol_security,
            "firmware_security": self.firmware_security,
        }

        for name, value in values.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{name} must be between 0.0 and 1.0"
                )

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


def build_mqtt_context(
    *,
    device_criticality: float,
    network_exposure: float,
    anonymous_access: bool,
    tls_enabled: bool,
    firmware_security: float,
) -> IoTContext:
    """
    Build IoT context for an MQTT-related finding.

    Security-oriented normalization:
        0.0 = lower risk contribution
        1.0 = higher risk contribution
    """

    authentication_security = 1.0 if anonymous_access else 0.0
    protocol_security = 1.0 if not tls_enabled else 0.0

    return IoTContext(
        device_criticality=device_criticality,
        network_exposure=network_exposure,
        authentication_security=authentication_security,
        protocol_security=protocol_security,
        firmware_security=firmware_security,
    )