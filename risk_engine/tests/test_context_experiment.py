"""
Controlled experiment demonstrating the effect of IoT context
on dynamic vulnerability risk.

The vulnerability and base severity remain constant.
Only the IoT-specific context changes.
"""

import os

from dotenv import load_dotenv
from scanner.mqtt_checks.mqtt_analyzer import analyze_mqtt
from risk_engine.features.iot_context import build_mqtt_context
from risk_engine.scoring.dynamic_risk import calculate_dynamic_risk


load_dotenv()

MQTT_BROKER_HOST = os.getenv("MQTT_BROKER_HOST", "127.0.0.1")
MQTT_BROKER_PORT = int(os.getenv("MQTT_BROKER_PORT", "1883"))


def run_experiment() -> None:

    # ---------------------------------------------------------
    # Same vulnerability for both experiments
    # ---------------------------------------------------------

    findings = analyze_mqtt(
        host=MQTT_BROKER_HOST,
        port=MQTT_BROKER_PORT,
        tls_enabled=False,
        anonymous_allowed=True,
        service="mosquitto",
        version="2.1.2",
        observed_topics=[
            "iot/esp32/01/sensor",
            "iot/esp32/02/sensor",
        ],
    )

    vulnerability = next(
        finding for finding in findings if finding.finding_type == "MQTT_WITHOUT_TLS"
    )

    # ---------------------------------------------------------
    # Experiment A
    # Low-criticality IoT sensor
    # ---------------------------------------------------------

    sensor_context = build_mqtt_context(
        device_criticality=0.3,
        network_exposure=0.3,
        anonymous_access=True,
        tls_enabled=False,
        firmware_security=0.5,
    )

    sensor_risk = calculate_dynamic_risk(
        base_severity=vulnerability.severity,
        context=sensor_context,
    )

    # ---------------------------------------------------------
    # Experiment B
    # High-criticality IoT device
    # ---------------------------------------------------------

    critical_context = build_mqtt_context(
        device_criticality=1.0,
        network_exposure=0.9,
        anonymous_access=True,
        tls_enabled=False,
        firmware_security=0.2,
    )

    critical_risk = calculate_dynamic_risk(
        base_severity=vulnerability.severity,
        context=critical_context,
    )

    # ---------------------------------------------------------
    # Results
    # ---------------------------------------------------------

    print("=" * 70)
    print("IoT CONTEXT-AWARE RISK EXPERIMENT")
    print("=" * 70)

    print()
    print("Fixed vulnerability:")
    print(f"  Finding: {vulnerability.finding_type}")
    print(f"  Severity: {vulnerability.severity}")

    print()
    print("-" * 70)
    print("EXPERIMENT A — LOW-CRITICALITY SENSOR")
    print("-" * 70)

    print("Context:")
    print(f"  Device Criticality: {sensor_context.device_criticality}")
    print(f"  Network Exposure: {sensor_context.network_exposure}")
    print(f"  Authentication Security: {sensor_context.authentication_security}")
    print(f"  Protocol Security: {sensor_context.protocol_security}")
    print(f"  Firmware Security: {sensor_context.firmware_security}")

    print(f"Dynamic Risk Score: {sensor_risk.score}")
    print(f"Risk Level: {sensor_risk.risk_level}")

    print()
    print("-" * 70)
    print("EXPERIMENT B — HIGH-CRITICALITY DEVICE")
    print("-" * 70)

    print("Context:")
    print(f"  Device Criticality: {critical_context.device_criticality}")
    print(f"  Network Exposure: {critical_context.network_exposure}")
    print(f"  Authentication Security: {critical_context.authentication_security}")
    print(f"  Protocol Security: {critical_context.protocol_security}")
    print(f"  Firmware Security: {critical_context.firmware_security}")

    print(f"Dynamic Risk Score: {critical_risk.score}")
    print(f"Risk Level: {critical_risk.risk_level}")

    # ---------------------------------------------------------
    # Comparison
    # ---------------------------------------------------------

    difference = round(
        critical_risk.score - sensor_risk.score,
        2,
    )

    print()
    print("=" * 70)
    print("EXPERIMENT COMPARISON")
    print("=" * 70)

    print(f"Sensor Risk Score:   {sensor_risk.score}")
    print(f"Critical Risk Score: {critical_risk.score}")
    print(f"Risk Difference:     {difference}")

    print()
    print("Conclusion:")
    print(
        "The vulnerability and base severity remained constant, "
        "while IoT-specific contextual factors changed."
    )

    print(
        "The resulting dynamic risk score therefore reflects "
        "the contextual conditions of the IoT asset."
    )


if __name__ == "__main__":
    run_experiment()
