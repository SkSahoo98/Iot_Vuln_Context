"""
Integration test for MQTT vulnerability detection + IoT risk scoring.
"""

import os

from dotenv import load_dotenv

from scanner.mqtt_checks.mqtt_analyzer import analyze_mqtt
from risk_engine.features.iot_context import build_mqtt_context
from risk_engine.scoring.dynamic_risk import calculate_dynamic_risk


# Load configuration from project .env
load_dotenv()

MQTT_BROKER_HOST = os.getenv("MQTT_BROKER_HOST", "127.0.0.1")
MQTT_BROKER_PORT = int(os.getenv("MQTT_BROKER_PORT", "1883"))


def main() -> None:
    # Evidence collected from the controlled IoT laboratory.
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

    context = build_mqtt_context(
        device_criticality=0.8,
        network_exposure=0.6,
        anonymous_access=True,
        tls_enabled=False,
        firmware_security=0.5,
    )

    print("=" * 60)
    print("MQTT SECURITY ASSESSMENT")
    print("=" * 60)

    print()
    print("MQTT Broker:", MQTT_BROKER_HOST)
    print("MQTT Port:", MQTT_BROKER_PORT)

    for finding in findings:
        risk = calculate_dynamic_risk(
            base_severity=finding.severity,
            context=context,
        )

        print()
        print("Finding:", finding.finding_type)
        print("Title:", finding.title)
        print("Severity:", finding.severity)
        print("Confidence:", finding.confidence)
        print("Risk Score:", risk.score)
        print("Risk Level:", risk.risk_level)
        print("Evidence:", finding.evidence)

        print("Factor Contributions:")

        for name, values in risk.factor_contributions.items():
            print(
                f"  {name}: "
                f"value={values['normalized_value']}, "
                f"weight={values['weight']}, "
                f"contribution={values['contribution_to_100']}"
            )


if __name__ == "__main__":
    main()