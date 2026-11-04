"""Deterministic remediation lifecycle, verification orchestration, and verdict engine."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.schemas.assessment import AssessmentDetailOut, AssessmentFindingOut
from app.schemas.remediation import (
    RemediationComparisonOut,
    RemediationConfirmRequest,
    RemediationVerificationOut,
    RemediationVerifyRequest,
    RemediationWorkflowOut,
)
from app.services.assessment_service import (
    DEFAULT_PROBES,
    AssessmentProbes,
    get_assessment,
    run_assessment,
)
from app.services.multi_device_coordinator import run_environment_assessment
from scanner.targets import TargetNotAllowedError, validate_target

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _json(value: object) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def make_finding_fingerprint(
    target: str,
    finding_id: str,
    port: int | None,
    finding_type: str = "",
) -> str:
    port_str = str(port) if port is not None else "none"
    return f"{target}::{finding_id}::{port_str}::{finding_type}"


def finding_key(finding: AssessmentFindingOut | dict[str, Any]) -> str:
    if isinstance(finding, dict):
        return json.dumps([finding.get("finding_id"), finding.get("target"), finding.get("port")])
    return json.dumps([finding.finding_id, finding.target, finding.port])


def _extract_checks_evaluated(metadata: dict[str, Any] | None) -> dict[str, str]:
    """Index checks_evaluated by f'{check_id}:{port}'."""
    if not metadata or not isinstance(metadata, dict):
        return {}
    raw = metadata.get("checks_evaluated")
    if not isinstance(raw, list):
        return {}
    res: dict[str, str] = {}
    for item in raw:
        if isinstance(item, dict) and "check_id" in item and "status" in item:
            port_key = str(item.get("port")) if item.get("port") is not None else "none"
            k = f"{item['check_id']}:{port_key}"
            res[k] = item["status"]
            # Also record check_id alone for scan-wide entries
            if item.get("port") is None:
                res[f"{item['check_id']}:scan_wide"] = item["status"]
    return res


def evaluate_verification_verdict(
    baseline_finding: dict[str, Any],
    baseline_assessment: AssessmentDetailOut,
    verification_assessment: AssessmentDetailOut,
) -> tuple[str, str, bool, bool, list[str]]:
    """Deterministic verdict calculation based on evidence and coverage equivalence.

    Returns:
        (verdict, rationale, coverage_equivalent, baseline_finding_present, evidence_refs)
    """
    target = baseline_finding["target"]
    finding_id = baseline_finding["finding_id"]
    port = baseline_finding.get("port")
    port_str = str(port) if port is not None else "none"

    # 1. Assessment run completion check
    if verification_assessment.status == "FAILED":
        return (
            "VERIFICATION_FAILED",
            f"Verification assessment failed with error: {verification_assessment.error_summary or 'internal scanner error'}",
            False,
            False,
            [],
        )
    if verification_assessment.status != "COMPLETE":
        return (
            "INCONCLUSIVE",
            f"Verification assessment is {verification_assessment.status} ({verification_assessment.error_summary or 'incomplete'}).",
            False,
            False,
            [],
        )

    # 2. Target reachability check from NMAP_SCAN evidence
    target_evidence = [
        e for e in verification_assessment.evidence
        if e.target == target
    ]
    nmap_scan_ev = next(
        (e for e in target_evidence if e.check_type == "NMAP_SCAN"),
        None,
    )
    if nmap_scan_ev:
        obs = nmap_scan_ev.observation if isinstance(nmap_scan_ev.observation, dict) else {}
        if obs.get("error_type") or obs.get("error"):
            return (
                "INCONCLUSIVE",
                f"Target {target} scan encountered network error: {obs.get('error', 'error')}",
                False,
                False,
                [str(nmap_scan_ev.id)],
            )
        if obs.get("target_responded") is False:
            return (
                "INCONCLUSIVE",
                f"Target {target} did not respond during verification scan. Absence of response cannot prove remediation.",
                False,
                False,
                [str(nmap_scan_ev.id)],
            )

    # 3. Coverage equivalence check
    checks_idx = _extract_checks_evaluated(verification_assessment.metadata)
    exact_key = f"{finding_id}:{port_str}"
    scan_wide_key = f"{finding_id}:scan_wide"

    check_status = checks_idx.get(exact_key) or checks_idx.get(scan_wide_key)

    # If the verification run is an environment assessment, also check child run metadata if available
    if not check_status and verification_assessment.metadata.get("devices"):
        for dev in verification_assessment.metadata.get("devices", []):
            if isinstance(dev, dict) and dev.get("ip") == target and dev.get("checks_evaluated"):
                dev_idx = _extract_checks_evaluated(dev)
                check_status = dev_idx.get(exact_key) or dev_idx.get(scan_wide_key)
                if check_status:
                    break

    # If finding is network check (NET-01, NET-06), check if ports were scanned
    is_network_check = finding_id.startswith("NET-")
    if is_network_check and not check_status:
        scanned_ports = verification_assessment.metadata.get("ports", [])
        if isinstance(scanned_ports, list) and (port in scanned_ports or port is None):
            check_status = "EVALUATED"

    # MQTT checks: if port 1883 was probed
    if finding_id.startswith("IOT-MQTT-") and not check_status:
        mqtt_evidence_present = any(
            e.target == target and (e.check_type.startswith("MQTT_") or e.port in (1883, 8883))
            for e in target_evidence
        )
        if mqtt_evidence_present:
            check_status = "EVALUATED"

    coverage_equivalent = (check_status == "EVALUATED")

    if not coverage_equivalent:
        return (
            "INCONCLUSIVE",
            f"Verification assessment did not evaluate check coverage for {finding_id} on {target}:{port_str} (status: {check_status or 'NOT_EVALUATED'}).",
            False,
            False,
            [str(e.id) for e in target_evidence[:3]],
        )

    # 4. Finding presence check in verification assessment
    matching_findings = [
        f for f in verification_assessment.findings
        if f.target == target and f.finding_id == finding_id and f.port == port
    ]

    evidence_refs = [
        str(f.evidence_reference)
        for f in matching_findings
        if f.evidence_reference
    ]
    if not evidence_refs:
        # Include relevant target evidence from verification
        evidence_refs = [
            str(e.id) for e in target_evidence
            if e.port == port or e.check_type.startswith(finding_id.split("-")[0])
        ]

    if matching_findings:
        mf = matching_findings[0]
        # Check for partial improvement: e.g. lower severity
        severity_ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        base_sev = baseline_finding.get("severity", "HIGH")
        new_sev = mf.severity
        if severity_ranks.get(new_sev, 0) < severity_ranks.get(base_sev, 0):
            return (
                "PARTIALLY_RESOLVED",
                f"Vulnerability remains detected on {target}:{port_str}, but severity decreased from {base_sev} to {new_sev}.",
                True,
                True,
                evidence_refs,
            )
        return (
            "STILL_PRESENT",
            f"Vulnerability {finding_id} was observed again on {target}:{port_str} in verification assessment.",
            True,
            True,
            evidence_refs,
        )

    # Finding not detected under equivalent coverage
    return (
        "VERIFIED_RESOLVED",
        f"Vulnerability {finding_id} on {target}:{port_str} is no longer detected under equivalent verification check coverage.",
        True,
        False,
        evidence_refs,
    )


def create_or_get_remediation(
    db: Session,
    baseline_assessment_id: UUID,
    baseline_finding_id: UUID,
) -> RemediationWorkflowOut:
    """Create a new remediation workflow or retrieve an existing one."""
    # Check baseline finding exists
    finding_row = db.execute(
        text(
            """
            SELECT id, assessment_id, finding_id, finding_type, category,
                   title, severity, confidence, description, target, port,
                   evidence_reference, remediation, status, created_at
            FROM assessment_findings
            WHERE id = :finding_id AND assessment_id = :assessment_id
            """
        ),
        {
            "finding_id": baseline_finding_id,
            "assessment_id": baseline_assessment_id,
        },
    ).mappings().fetchone()

    if not finding_row:
        raise ValueError(
            f"Baseline finding {baseline_finding_id} not found in assessment {baseline_assessment_id}"
        )

    fingerprint = make_finding_fingerprint(
        target=finding_row["target"],
        finding_id=finding_row["finding_id"],
        port=finding_row["port"],
        finding_type=finding_row["finding_type"],
    )

    # Check if workflow already exists for this baseline finding
    existing = db.execute(
        text(
            """
            SELECT id, baseline_assessment_id, baseline_finding_id,
                   finding_fingerprint, target, status, guidance_version,
                   user_confirmed_at, verification_assessment_id,
                   verification_verdict, verdict_rationale, coverage_summary,
                   created_at, updated_at
            FROM remediation_workflows
            WHERE baseline_finding_id = :baseline_finding_id
            ORDER BY created_at DESC
            LIMIT 1
            """
        ),
        {"baseline_finding_id": baseline_finding_id},
    ).mappings().fetchone()

    if existing:
        return _build_workflow_out(db, dict(existing), dict(finding_row))

    # Insert new workflow
    workflow_id = db.execute(
        text(
            """
            INSERT INTO remediation_workflows
                (baseline_assessment_id, baseline_finding_id,
                 finding_fingerprint, target, status, guidance_version)
            VALUES
                (:baseline_assessment_id, :baseline_finding_id,
                 :fingerprint, :target, 'OPEN', '1.0')
            RETURNING id
            """
        ),
        {
            "baseline_assessment_id": baseline_assessment_id,
            "baseline_finding_id": baseline_finding_id,
            "fingerprint": fingerprint,
            "target": finding_row["target"],
        },
    ).scalar_one()
    db.commit()

    created = db.execute(
        text(
            """
            SELECT id, baseline_assessment_id, baseline_finding_id,
                   finding_fingerprint, target, status, guidance_version,
                   user_confirmed_at, verification_assessment_id,
                   verification_verdict, verdict_rationale, coverage_summary,
                   created_at, updated_at
            FROM remediation_workflows
            WHERE id = :id
            """
        ),
        {"id": workflow_id},
    ).mappings().one()

    return _build_workflow_out(db, dict(created), dict(finding_row))


def get_remediation(db: Session, workflow_id: UUID) -> RemediationWorkflowOut | None:
    row = db.execute(
        text(
            """
            SELECT id, baseline_assessment_id, baseline_finding_id,
                   finding_fingerprint, target, status, guidance_version,
                   user_confirmed_at, verification_assessment_id,
                   verification_verdict, verdict_rationale, coverage_summary,
                   created_at, updated_at
            FROM remediation_workflows
            WHERE id = :id
            """
        ),
        {"id": workflow_id},
    ).mappings().fetchone()

    if not row:
        return None

    finding_row = db.execute(
        text(
            """
            SELECT id, assessment_id, finding_id, finding_type, category,
                   title, severity, confidence, description, target, port,
                   evidence_reference, remediation, status, created_at
            FROM assessment_findings
            WHERE id = :id
            """
        ),
        {"id": row["baseline_finding_id"]},
    ).mappings().fetchone()

    return _build_workflow_out(db, dict(row), dict(finding_row) if finding_row else None)


def list_remediations(
    db: Session,
    baseline_assessment_id: UUID | None = None,
) -> list[RemediationWorkflowOut]:
    sql = """
        SELECT id, baseline_assessment_id, baseline_finding_id,
               finding_fingerprint, target, status, guidance_version,
               user_confirmed_at, verification_assessment_id,
               verification_verdict, verdict_rationale, coverage_summary,
               created_at, updated_at
        FROM remediation_workflows
    """
    params: dict[str, Any] = {}
    if baseline_assessment_id:
        sql += " WHERE baseline_assessment_id = :assessment_id"
        params["assessment_id"] = baseline_assessment_id
    sql += " ORDER BY created_at DESC"

    rows = db.execute(text(sql), params).mappings().fetchall()
    return [_build_workflow_out(db, dict(r)) for r in rows]


def confirm_remediation(
    db: Session,
    workflow_id: UUID,
    request: RemediationConfirmRequest,
) -> RemediationWorkflowOut:
    """Record user confirmation that remediation was applied.

    Moves state to READY_FOR_VERIFICATION. NEVER marks as VERIFIED_RESOLVED.
    """
    workflow = get_remediation(db, workflow_id)
    if not workflow:
        raise ValueError(f"Remediation workflow {workflow_id} not found")

    now = _utc_now()
    coverage_summary = dict(workflow.coverage_summary)
    if request.notes:
        coverage_summary["user_confirmation_notes"] = request.notes

    db.execute(
        text(
            """
            UPDATE remediation_workflows
            SET status = 'READY_FOR_VERIFICATION',
                user_confirmed_at = :now,
                coverage_summary = CAST(:coverage_summary AS jsonb),
                updated_at = :now
            WHERE id = :id
            """
        ),
        {
            "id": workflow_id,
            "now": now,
            "coverage_summary": _json(coverage_summary),
        },
    )
    db.commit()

    return get_remediation(db, workflow_id)  # type: ignore[return-value]


def verify_remediation(
    db: Session,
    settings: Settings,
    workflow_id: UUID,
    request: RemediationVerifyRequest,
    probes: AssessmentProbes = DEFAULT_PROBES,
) -> RemediationWorkflowOut:
    """Run an authorized verification assessment and calculate deterministic verdict.

    Requires explicit user approval (request.explicit_approval == True).
    """
    if not request.explicit_approval:
        raise ValueError("Explicit user approval is required to run verification assessment.")

    workflow = get_remediation(db, workflow_id)
    if not workflow:
        raise ValueError(f"Remediation workflow {workflow_id} not found")

    # Retrieve baseline finding and assessment
    baseline_assessment = get_assessment(db, workflow.baseline_assessment_id)
    if not baseline_assessment:
        raise ValueError(f"Baseline assessment {workflow.baseline_assessment_id} not found")

    baseline_finding = next(
        (f for f in baseline_assessment.findings if f.id == workflow.baseline_finding_id),
        None,
    )
    if not baseline_finding:
        raise ValueError(f"Baseline finding {workflow.baseline_finding_id} not found in assessment")

    # Authorize verification target server-side
    validate_target(workflow.target, settings.assessment_allowed_targets)

    # Update workflow to VERIFICATION_PENDING
    now = _utc_now()
    db.execute(
        text(
            """
            UPDATE remediation_workflows
            SET status = 'VERIFICATION_PENDING',
                updated_at = :now
            WHERE id = :id
            """
        ),
        {"id": workflow_id, "now": now},
    )
    db.commit()

    # Determine assessment scope to run
    verification_assessment: AssessmentDetailOut
    if request.scope == "ENVIRONMENT" or (
        request.scope == "AUTO" and baseline_assessment.assessment_type == "ENVIRONMENT"
    ):
        verification_assessment = run_environment_assessment(
            db, settings, probes=probes
        )
    else:
        verification_assessment = run_assessment(
            db, settings, workflow.target, probes=probes
        )

    # Deterministic verdict engine
    verdict, rationale, coverage_equiv, finding_present, evidence_refs = evaluate_verification_verdict(
        baseline_finding=baseline_finding.model_dump(),
        baseline_assessment=baseline_assessment,
        verification_assessment=verification_assessment,
    )

    # Compute risk delta
    base_snapshot = next(
        (s for s in baseline_assessment.risk_snapshots if s.finding_ref == baseline_finding.id),
        None,
    )
    verif_matching_finding = next(
        (
            f for f in verification_assessment.findings
            if f.target == workflow.target
            and f.finding_id == baseline_finding.finding_id
            and f.port == baseline_finding.port
        ),
        None,
    )
    verif_snapshot = next(
        (
            s for s in verification_assessment.risk_snapshots
            if verif_matching_finding and s.finding_ref == verif_matching_finding.id
        ),
        None,
    )

    risk_delta: dict[str, Any] = {
        "baseline_score": base_snapshot.score if base_snapshot else None,
        "verification_score": verif_snapshot.score if verif_snapshot else None,
        "delta": (
            round(verif_snapshot.score - base_snapshot.score, 2)
            if base_snapshot and verif_snapshot
            else (
                -round(base_snapshot.score, 2)
                if base_snapshot and verdict == "VERIFIED_RESOLVED"
                else None
            )
        ),
        "baseline_overall": baseline_assessment.highest_risk,
        "verification_overall": verification_assessment.highest_risk,
    }

    # Record verification in remediation_verifications table
    verif_id = db.execute(
        text(
            """
            INSERT INTO remediation_verifications
                (workflow_id, verification_assessment_id, verdict,
                 verdict_rationale, coverage_equivalent, baseline_finding_present,
                 evidence_references, risk_delta)
            VALUES
                (:workflow_id, :verification_assessment_id, :verdict,
                 :verdict_rationale, :coverage_equivalent, :baseline_finding_present,
                 CAST(:evidence_references AS jsonb), CAST(:risk_delta AS jsonb))
            RETURNING id
            """
        ),
        {
            "workflow_id": workflow_id,
            "verification_assessment_id": verification_assessment.id,
            "verdict": verdict,
            "verdict_rationale": rationale,
            "coverage_equivalent": coverage_equiv,
            "baseline_finding_present": finding_present,
            "evidence_references": _json(evidence_refs),
            "risk_delta": _json(risk_delta),
        },
    ).scalar_one()

    # Update remediation_workflows table
    cov_summary = {
        "coverage_equivalent": coverage_equiv,
        "verification_assessment_id": str(verification_assessment.id),
        "verification_status": verification_assessment.status,
        "last_verification_id": str(verif_id),
    }

    db.execute(
        text(
            """
            UPDATE remediation_workflows
            SET status = :verdict,
                verification_assessment_id = :verification_assessment_id,
                verification_verdict = :verdict,
                verdict_rationale = :rationale,
                coverage_summary = CAST(:cov_summary AS jsonb),
                updated_at = :now
            WHERE id = :id
            """
        ),
        {
            "id": workflow_id,
            "verdict": verdict,
            "verification_assessment_id": verification_assessment.id,
            "rationale": rationale,
            "cov_summary": _json(cov_summary),
            "now": _utc_now(),
        },
    )
    db.commit()

    return get_remediation(db, workflow_id)  # type: ignore[return-value]


def get_remediation_comparison(
    db: Session,
    workflow_id: UUID,
) -> RemediationComparisonOut:
    workflow = get_remediation(db, workflow_id)
    if not workflow:
        raise ValueError(f"Remediation workflow {workflow_id} not found")

    baseline_assessment = get_assessment(db, workflow.baseline_assessment_id)
    if not baseline_assessment:
        raise ValueError("Baseline assessment not found")

    baseline_finding = next(
        (f for f in baseline_assessment.findings if f.id == workflow.baseline_finding_id),
        None,
    )
    base_snapshot = next(
        (s for s in baseline_assessment.risk_snapshots if s.finding_ref == workflow.baseline_finding_id),
        None,
    )
    base_evidence = [
        e.model_dump()
        for e in baseline_assessment.evidence
        if baseline_finding and (
            e.id == baseline_finding.evidence_reference or e.target == workflow.target
        )
    ]

    baseline_data: dict[str, Any] = {
        "assessment_id": str(baseline_assessment.id),
        "target": baseline_assessment.target,
        "started_at": baseline_assessment.started_at,
        "finding": baseline_finding.model_dump() if baseline_finding else None,
        "risk_snapshot": base_snapshot.model_dump() if base_snapshot else None,
        "evidence": base_evidence,
    }

    verification_data: dict[str, Any] | None = None
    if workflow.verification_assessment_id:
        verif_assessment = get_assessment(db, workflow.verification_assessment_id)
        if verif_assessment:
            verif_matching = next(
                (
                    f for f in verif_assessment.findings
                    if baseline_finding
                    and f.target == workflow.target
                    and f.finding_id == baseline_finding.finding_id
                    and f.port == baseline_finding.port
                ),
                None,
            )
            verif_snapshot = next(
                (
                    s for s in verif_assessment.risk_snapshots
                    if verif_matching and s.finding_ref == verif_matching.id
                ),
                None,
            )
            verif_evidence = [
                e.model_dump()
                for e in verif_assessment.evidence
                if e.target == workflow.target
            ]
            verification_data = {
                "assessment_id": str(verif_assessment.id),
                "target": verif_assessment.target,
                "status": verif_assessment.status,
                "started_at": verif_assessment.started_at,
                "finding_found": verif_matching is not None,
                "finding": verif_matching.model_dump() if verif_matching else None,
                "risk_snapshot": verif_snapshot.model_dump() if verif_snapshot else None,
                "evidence": verif_evidence,
            }

    latest_verif = workflow.verifications[0] if workflow.verifications else None

    return RemediationComparisonOut(
        workflow=workflow,
        baseline=baseline_data,
        verification=verification_data,
        verdict=workflow.verification_verdict or "NOT_VERIFIED",
        verdict_rationale=workflow.verdict_rationale,
        coverage_equivalent=latest_verif.coverage_equivalent if latest_verif else False,
        risk_delta=latest_verif.risk_delta if latest_verif else None,
    )


def _build_workflow_out(
    db: Session,
    row: dict[str, Any],
    finding_details: dict[str, Any] | None = None,
) -> RemediationWorkflowOut:
    verif_rows = db.execute(
        text(
            """
            SELECT id, workflow_id, verification_assessment_id, verdict,
                   verdict_rationale, coverage_equivalent, baseline_finding_present,
                   evidence_references, risk_delta, created_at
            FROM remediation_verifications
            WHERE workflow_id = :workflow_id
            ORDER BY created_at DESC
            """
        ),
        {"workflow_id": row["id"]},
    ).mappings().fetchall()

    verifications = [
        RemediationVerificationOut(
            id=v["id"],
            workflow_id=v["workflow_id"],
            verification_assessment_id=v["verification_assessment_id"],
            verdict=v["verdict"],
            verdict_rationale=v["verdict_rationale"],
            coverage_equivalent=v["coverage_equivalent"],
            baseline_finding_present=v["baseline_finding_present"],
            evidence_references=(
                v["evidence_references"] if isinstance(v["evidence_references"], list)
                else json.loads(v["evidence_references"] or "[]")
            ),
            risk_delta=v["risk_delta"] if isinstance(v["risk_delta"], dict) else (
                json.loads(v["risk_delta"]) if v["risk_delta"] else None
            ),
            created_at=v["created_at"],
        )
        for v in verif_rows
    ]

    cov = row.get("coverage_summary")
    if isinstance(cov, str):
        cov = json.loads(cov)
    elif not isinstance(cov, dict):
        cov = {}

    return RemediationWorkflowOut(
        id=row["id"],
        baseline_assessment_id=row["baseline_assessment_id"],
        baseline_finding_id=row["baseline_finding_id"],
        finding_fingerprint=row["finding_fingerprint"],
        target=row["target"],
        status=row["status"],
        guidance_version=row.get("guidance_version", "1.0"),
        user_confirmed_at=row.get("user_confirmed_at"),
        verification_assessment_id=row.get("verification_assessment_id"),
        verification_verdict=row.get("verification_verdict"),
        verdict_rationale=row.get("verdict_rationale"),
        coverage_summary=cov,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        verifications=verifications,
        finding_details=finding_details,
    )
