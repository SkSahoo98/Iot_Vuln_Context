"""Evidence-driven MQTT findings (IOT-MQTT-*)."""

from __future__ import annotations

from scanner.core.findings import make_finding
from scanner.core.models import Evidence, FindingCandidate


def evaluate_mqtt(
    anonymous_evidence: Evidence,
    tls_evidence: Evidence,
) -> list[FindingCandidate]:
    """Evaluate observed MQTT and TLS results.

    Configuration is deliberately not accepted. Anonymous access requires an
    accepted unauthenticated CONNACK. Missing TLS requires both an accepted
    plaintext MQTT session and an active TLS probe result showing unavailable.
    """
    findings: list[FindingCandidate] = []
    if anonymous_evidence.result != "ACCEPTED":
        return findings

    findings.append(
        make_finding(
            "IOT-MQTT-01",
            anonymous_evidence,
            description=(
                "The broker accepted an MQTT CONNECT without a username or "
                f"password (CONNACK reason code "
                f"{anonymous_evidence.observation.get('reason_code')}). "
                "Publish, subscribe, and topic-ACL permissions were not tested."
            ),
            confidence=0.99,
        )
    )

    broker_version = anonymous_evidence.observation.get("broker_version")
    if isinstance(broker_version, str) and broker_version.strip():
        findings.append(
            make_finding(
                "IOT-MQTT-03",
                anonymous_evidence,
                description=(
                    "The broker returned the following observed value from "
                    f"$SYS/broker/version: {broker_version.strip()[:200]}."
                ),
                confidence=0.99,
            )
        )

    if tls_evidence.result in {"REFUSED", "TIMEOUT", "UNAVAILABLE"}:
        combined = Evidence(
            target=anonymous_evidence.target,
            port=anonymous_evidence.port,
            check_type="MQTT_TRANSPORT_COMPARISON",
            result="PLAINTEXT_NO_TLS",
            evidence_source="MQTT_PROBE",
            observation={
                "plaintext_port": anonymous_evidence.port,
                "plaintext_connection": "ACCEPTED",
                "plaintext_connack_reason_code": anonymous_evidence.observation.get(
                    "reason_code"
                ),
                "tls_port": tls_evidence.port,
                "tls_result": tls_evidence.result,
                "tls_observation": tls_evidence.observation,
            },
        )
        findings.append(
            make_finding(
                "IOT-MQTT-02",
                combined,
                description=(
                    f"Plaintext MQTT was accepted on TCP "
                    f"{anonymous_evidence.port}; an active TLS handshake on TCP "
                    f"{tls_evidence.port} returned {tls_evidence.result}."
                ),
                confidence=0.95,
            )
        )
    return findings
