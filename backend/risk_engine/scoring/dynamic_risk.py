"""
Explainable IoT-specific dynamic risk scoring.

This deterministic baseline combines vulnerability severity with
IoT-specific contextual factors and exposes individual contributions.
"""

from __future__ import annotations

from dataclasses import dataclass

from risk_engine.features.iot_context import IoTContext

from risk_engine.rules.risk_rules import (
    RISK_SCORE_VERSION,
    BASE_SEVERITY_WEIGHT,
    CONTEXT_WEIGHT,
    RISK_FACTOR_WEIGHTS,
)


BASE_SEVERITY = {
    "INFO": 0.0,
    "LOW": 0.25,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}


@dataclass
class RiskResult:
    score: float
    risk_level: str
    score_version: str
    calculation_method: str
    base_severity: str
    base_severity_contribution: float
    context_score: float
    factor_contributions: dict[str, dict[str, float]]
    factors: dict[str, float]


def _risk_level(score: float) -> str:
    if score < 20:
        return "LOW"
    if score < 40:
        return "MODERATE"
    if score < 60:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "CRITICAL"


def calculate_dynamic_risk(
    *,
    base_severity: str,
    context: IoTContext,
) -> RiskResult:
    """
    Calculate an IoT-specific dynamic risk score.

    The score combines:
    - vulnerability severity
    - IoT-specific contextual factors

    The relative contribution of severity and context is controlled
    through BASE_SEVERITY_WEIGHT and CONTEXT_WEIGHT.
    """

    severity_name = base_severity.upper()
    severity_value = BASE_SEVERITY.get(severity_name)

    if severity_value is None:
        raise ValueError(
            f"Unsupported severity: {base_severity}"
        )

    weights = RISK_FACTOR_WEIGHTS

    factors = context.to_dict()

    factor_contributions = {}

    for name, weight in weights.items():
        value = factors[name]

        factor_contributions[name] = {
            "normalized_value": value,
            "weight": weight,
            "contribution_to_100": round(
                value * weight * 100 * CONTEXT_WEIGHT,
                2,
            ),
        }

    context_score = sum(
        factors[name] * weight
        for name, weight in weights.items()
    )

    base_severity_contribution = (
        severity_value * 100 * BASE_SEVERITY_WEIGHT
    )

    context_contribution = (
        context_score * 100 * CONTEXT_WEIGHT
    )

    score = round(
        base_severity_contribution + context_contribution,
        2,
    )

    score = max(0.0, min(100.0, score))

    return RiskResult(
        score=score,
        risk_level=_risk_level(score),
        score_version=RISK_SCORE_VERSION,
        calculation_method="severity_context_weighted",
        base_severity=severity_name,
        base_severity_contribution=round(
            base_severity_contribution,
            2,
        ),
        context_score=round(
            context_score,
            4,
        ),
        factor_contributions=factor_contributions,
        factors=factors,
    )