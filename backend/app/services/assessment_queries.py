"""Read-only assessment queries (SELECT only; no scanner or probe imports)."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.schemas.assessment import AssessmentDetailOut, AssessmentSummaryOut
from app.services.risk_trace import build_risk_trace

_SUMMARY_SQL = """
    SELECT
        r.id, r.target, r.assessment_type, r.status, r.started_at,
        r.completed_at, r.error_summary, r.metadata, r.created_at,
        (SELECT COUNT(*) FROM assessment_evidence e
         WHERE e.assessment_id = r.id) AS evidence_count,
        (SELECT COUNT(*) FROM assessment_findings f
         WHERE f.assessment_id = r.id) AS finding_count,
        (SELECT rs.score FROM risk_snapshots rs
         WHERE rs.assessment_id = r.id AND rs.finding_ref IS NULL
         ORDER BY rs.created_at DESC LIMIT 1) AS highest_risk,
        (SELECT rs.risk_level FROM risk_snapshots rs
         WHERE rs.assessment_id = r.id AND rs.finding_ref IS NULL
         ORDER BY rs.created_at DESC LIMIT 1) AS highest_risk_level
    FROM assessment_runs r
"""


def list_assessments(db: Session) -> list[AssessmentSummaryOut]:
    rows = db.execute(
        text(_SUMMARY_SQL + " ORDER BY r.started_at DESC, r.completed_at DESC NULLS LAST, r.created_at DESC")
    ).mappings()
    return [AssessmentSummaryOut.model_validate(dict(row)) for row in rows]


def get_assessment(
    db: Session,
    assessment_id: UUID,
) -> AssessmentDetailOut | None:
    run = db.execute(
        text(_SUMMARY_SQL + " WHERE r.id = :assessment_id"),
        {"assessment_id": assessment_id},
    ).mappings().one_or_none()
    if run is None:
        return None

    evidence = db.execute(
        text(
            """
            SELECT id, assessment_id, target, port, check_type, result,
                   evidence_source, observation, observed_at
            FROM assessment_evidence
            WHERE assessment_id = :assessment_id
            ORDER BY observed_at, id
            """
        ),
        {"assessment_id": assessment_id},
    ).mappings()
    findings = db.execute(
        text(
            """
            SELECT id, assessment_id, finding_id, finding_type, category,
                   title, severity, confidence, description, target, port,
                   evidence_reference, remediation, status, created_at
            FROM assessment_findings
            WHERE assessment_id = :assessment_id
            ORDER BY created_at, finding_id
            """
        ),
        {"assessment_id": assessment_id},
    ).mappings()
    risks = db.execute(
        text(
            """
            SELECT id, assessment_id, finding_ref, score, risk_level,
                   score_version, base_severity, context_score,
                   factor_contributions, context_inputs, created_at
            FROM risk_snapshots
            WHERE assessment_id = :assessment_id
            ORDER BY created_at, id
            """
        ),
        {"assessment_id": assessment_id},
    ).mappings()

    detail = AssessmentDetailOut.model_validate(
        {
            **dict(run),
            "evidence": [dict(row) for row in evidence],
            "findings": [dict(row) for row in findings],
            "risk_snapshots": [dict(row) for row in risks],
        }
    )
    detail.risk_trace = build_risk_trace(
        detail.evidence, detail.findings, detail.risk_snapshots
    )
    return detail
