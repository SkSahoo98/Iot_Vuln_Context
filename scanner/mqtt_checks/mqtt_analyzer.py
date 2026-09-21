"""
Evidence-backed MQTT security checks.

This module does not assume that every MQTT service is vulnerable.
It evaluates explicit evidence for:
    - MQTT without TLS
    - MQTT anonymous access

The output is normalized finding data that can later be persisted
through the backend/database layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MQTTFinding:
    finding_type: str
    title: str
    severity: str
    confidence: float
    description: str
    impact: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)


def check_mqtt_without_tls(
    *,
    port: int,
    tls_enabled: bool,
    evidence: dict[str, Any] | None = None,
) -> MQTTFinding | None:
    """
    Detect MQTT operating without TLS.

    Port 1883 alone does NOT prove a vulnerability.
    An explicit indication that TLS is not enabled is required.
    """

    if port != 1883:
        return None

    if tls_enabled:
        return None

    return MQTTFinding(
        finding_type="MQTT_WITHOUT_TLS",
        title="MQTT communication without TLS",
        severity="HIGH",
        confidence=0.98,
        description=(
            "The MQTT service is operating without transport encryption. "
            "MQTT application traffic may therefore be observable in "
            "plaintext by an authorized network observer."
        ),
        impact=(
            "Potential loss of confidentiality of MQTT metadata and "
            "application payloads transmitted across the network."
        ),
        recommendation=(
            "Enable MQTT over TLS and configure clients to validate the "
            "broker certificate."
        ),
        evidence=evidence or {},
    )


def check_mqtt_anonymous_access(
    *,
    anonymous_allowed: bool,
    evidence: dict[str, Any] | None = None,
) -> MQTTFinding | None:
    """
    Detect an MQTT broker that permits anonymous clients.
    """

    if not anonymous_allowed:
        return None

    return MQTTFinding(
        finding_type="MQTT_ANONYMOUS_ACCESS",
        title="MQTT broker allows anonymous access",
        severity="HIGH",
        confidence=0.99,
        description=(
            "The MQTT broker permits client connections without "
            "authentication."
        ),
        impact=(
            "Unauthenticated clients may gain access to MQTT resources "
            "depending on the broker's topic authorization configuration."
        ),
        recommendation=(
            "Disable anonymous access and require authenticated MQTT "
            "clients with topic-level authorization."
        ),
        evidence=evidence or {},
    )


def analyze_mqtt(
    *,
    host: str,
    port: int = 1883,
    tls_enabled: bool = False,
    anonymous_allowed: bool = False,
    service: str | None = None,
    version: str | None = None,
    observed_topics: list[str] | None = None,
) -> list[MQTTFinding]:
    """
    Run evidence-backed MQTT security checks.

    Returns only findings supported by the supplied evidence.
    """

    common_evidence = {
        "host": host,
        "port": port,
        "service": service,
        "version": version,
        "observed_topics": observed_topics or [],
    }

    findings: list[MQTTFinding] = []

    tls_finding = check_mqtt_without_tls(
        port=port,
        tls_enabled=tls_enabled,
        evidence={
            **common_evidence,
            "tls_enabled": tls_enabled,
        },
    )

    if tls_finding:
        findings.append(tls_finding)

    anonymous_finding = check_mqtt_anonymous_access(
        anonymous_allowed=anonymous_allowed,
        evidence={
            **common_evidence,
            "anonymous_allowed": anonymous_allowed,
        },
    )

    if anonymous_finding:
        findings.append(anonymous_finding)

    return findings