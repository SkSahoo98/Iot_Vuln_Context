"""Evidence-backed finding service using the existing MQTT analyzer."""

from __future__ import annotations

import sys
from pathlib import Path

from app.core.config import Settings
from app.schemas.api import FindingOut

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.mqtt_checks.mqtt_analyzer import analyze_mqtt  # noqa: E402


def list_findings(settings: Settings) -> list[FindingOut]:
    """
    Produce findings from configured lab MQTT evidence.

    Does not invent closed-port vulnerabilities. Findings are returned
    only when the analyzer has supporting evidence flags.
    """
    topics = [
        topic.strip()
        for topic in settings.mqtt_observed_topics.split(",")
        if topic.strip()
    ]

    mqtt_findings = analyze_mqtt(
        host=settings.mqtt_broker_host,
        port=settings.mqtt_broker_port,
        tls_enabled=settings.mqtt_tls_enabled,
        anonymous_allowed=settings.mqtt_anonymous_allowed,
        service=settings.mqtt_service_name,
        version=settings.mqtt_service_version,
        observed_topics=topics,
    )

    return [
        FindingOut(
            finding_type=item.finding_type,
            title=item.title,
            severity=item.severity,
            confidence=item.confidence,
            description=item.description,
            impact=item.impact,
            recommendation=item.recommendation,
            evidence=item.evidence,
        )
        for item in mqtt_findings
    ]
