"""Read-only finding -> risk factor trace for recorded assessments.

The IoT-RISK-v1 context rules below are shared with
``assessment_service._risk_context`` so the trace and the persisted risk
inputs cannot drift. The trace only joins recorded IDs; it never scores.
"""

from __future__ import annotations

from typing import Iterable
from uuid import UUID

from app.schemas.assessment import (
    AssessmentEvidenceOut,
    AssessmentFindingOut,
    RiskSnapshotOut,
    RiskTraceFactorOut,
    RiskTraceOut,
)

# Must equal risk_engine.rules.risk_rules.RISK_SCORE_VERSION (tested).
TRACE_SCORE_VERSION = "IoT-RISK-v1"

AUTHENTICATION_FINDING_TYPES = frozenset({"MQTT_ANONYMOUS_ACCESS"})
PROTOCOL_FINDING_TYPES = frozenset(
    {"MQTT_WITHOUT_TLS", "HTTP_PLAINTEXT", "OUTDATED_TLS_VERSION"}
)

# network_exposure counts scan.open_ports; the scanner records exactly one
# NMAP_PORT/OPEN evidence row per open port.
OPEN_PORT_EVIDENCE = ("NMAP_PORT", "OPEN")

CONFIGURED_FACTORS = ("device_criticality", "firmware_security")


def _finding_type_factor(
    factor: str,
    finding_types: frozenset[str],
    findings: list[AssessmentFindingOut],
) -> RiskTraceFactorOut:
    linked = [f for f in findings if f.finding_type in finding_types]
    return RiskTraceFactorOut(
        factor=factor,
        rule="FINDING_TYPE",
        finding_refs=[f.id for f in linked],
        evidence_refs=[
            f.evidence_reference for f in linked if f.evidence_reference
        ],
    )


def build_risk_trace(
    evidence: Iterable[AssessmentEvidenceOut],
    findings: Iterable[AssessmentFindingOut],
    snapshots: Iterable[RiskSnapshotOut],
) -> RiskTraceOut | None:
    snapshot_list = list(snapshots)
    overall = [s for s in snapshot_list if s.finding_ref is None]
    if not overall:
        return None
    latest_overall = max(overall, key=lambda s: s.created_at)
    if latest_overall.score_version != TRACE_SCORE_VERSION:
        return None

    finding_list = list(findings)
    open_port_ids = {
        e.id
        for e in evidence
        if (e.check_type, e.result) == OPEN_PORT_EVIDENCE
    }
    exposure_findings = [
        f for f in finding_list if f.evidence_reference in open_port_ids
    ]

    factors = [
        _finding_type_factor(
            "authentication_security",
            AUTHENTICATION_FINDING_TYPES,
            finding_list,
        ),
        _finding_type_factor(
            "protocol_security", PROTOCOL_FINDING_TYPES, finding_list
        ),
        RiskTraceFactorOut(
            factor="network_exposure",
            rule="OPEN_PORT_EVIDENCE",
            finding_refs=[f.id for f in exposure_findings],
            evidence_refs=sorted(open_port_ids, key=str),
        ),
        *(
            RiskTraceFactorOut(factor=name, rule="CONFIGURATION")
            for name in CONFIGURED_FACTORS
        ),
    ]

    determined_by: list[UUID] = [
        s.finding_ref
        for s in snapshot_list
        if s.finding_ref is not None
        and s.score == latest_overall.score
        and s.risk_level == latest_overall.risk_level
    ]
    return RiskTraceOut(
        score_version=latest_overall.score_version,
        overall_rule="HIGHEST_FINDING_RISK",
        overall_finding_refs=determined_by,
        factors=factors,
    )
