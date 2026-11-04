"""
IoT-RISK-v1 scoring rules.

These weights define the deterministic baseline model used for
the initial research experiment.

Weights sum to 1.0.
"""

RISK_SCORE_VERSION = "IoT-RISK-v1"

BASE_SEVERITY_WEIGHT = 0.50
CONTEXT_WEIGHT = 0.50

RISK_FACTOR_WEIGHTS = {
    "device_criticality": 0.30,
    "network_exposure": 0.20,
    "authentication_security": 0.20,
    "protocol_security": 0.20,
    "firmware_security": 0.10,
}


def validate_weights() -> None:
    """Ensure the configured factor weights are valid."""

    total = sum(RISK_FACTOR_WEIGHTS.values())

    if abs(total - 1.0) > 1e-9:
        raise ValueError(
            f"Risk factor weights must sum to 1.0, got {total}"
        )

    if not 0.0 <= BASE_SEVERITY_WEIGHT <= 1.0:
        raise ValueError("Invalid base severity weight.")

    if not 0.0 <= CONTEXT_WEIGHT <= 1.0:
        raise ValueError("Invalid context weight.")

    if abs(
        BASE_SEVERITY_WEIGHT + CONTEXT_WEIGHT - 1.0
    ) > 1e-9:
        raise ValueError(
            "Base severity weight and context weight must sum to 1.0."
        )


validate_weights()