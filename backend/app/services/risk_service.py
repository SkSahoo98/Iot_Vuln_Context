"""Risk assessment service — calls the existing IoT-RISK-v1 engine."""

from __future__ import annotations

import sys
from pathlib import Path

from app.core.config import Settings
from app.schemas.api import RiskItemOut, RiskSummaryOut
from app.services.finding_service import list_findings

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from risk_engine.features.iot_context import build_mqtt_context  # noqa: E402
from risk_engine.scoring.dynamic_risk import calculate_dynamic_risk  # noqa: E402


def assess_risk(settings: Settings) -> RiskSummaryOut:
    """Score current evidence-backed findings with the dynamic risk engine."""
    findings = list_findings(settings)
    context = build_mqtt_context(
        device_criticality=settings.risk_device_criticality,
        network_exposure=settings.risk_network_exposure,
        anonymous_access=settings.mqtt_anonymous_allowed,
        tls_enabled=settings.mqtt_tls_enabled,
        firmware_security=settings.risk_firmware_security,
    )

    items: list[RiskItemOut] = []
    for finding in findings:
        result = calculate_dynamic_risk(
            base_severity=finding.severity,
            context=context,
        )
        items.append(
            RiskItemOut(
                finding_type=finding.finding_type,
                base_severity=result.base_severity,
                score=result.score,
                risk_level=result.risk_level,
                score_version=result.score_version,
                calculation_method=result.calculation_method,
                base_severity_contribution=result.base_severity_contribution,
                context_score=result.context_score,
                factors=result.factors,
                factor_contributions=result.factor_contributions,
                evidence=finding.evidence,
            )
        )

    highest = max(items, key=lambda item: item.score) if items else None
    score_version = items[0].score_version if items else "IoT-RISK-v1"

    return RiskSummaryOut(
        score_version=score_version,
        mqtt_broker_host=settings.mqtt_broker_host,
        mqtt_broker_port=settings.mqtt_broker_port,
        findings_assessed=len(items),
        highest_score=highest.score if highest else None,
        highest_level=highest.risk_level if highest else None,
        items=items,
    )
