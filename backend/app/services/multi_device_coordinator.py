"""Multi-device IoT assessment coordination and aggregate security posture."""

from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.schemas.assessment import AssessmentDetailOut
from app.services.assessment_queries import get_assessment
from app.services.assessment_service import (
    DEFAULT_PROBES,
    AssessmentProbes,
    _json,
    _utc_now,
    run_assessment,
)
from app.services.device_service import list_devices
from scanner.targets import TargetNotAllowedError, parse_allowed_targets, validate_target

logger = logging.getLogger(__name__)

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

INFRASTRUCTURE_TYPES = frozenset(
    {"MQTT_BROKER", "BROKER", "GATEWAY", "INFRASTRUCTURE", "ROUTER", "MOSQUITTO"}
)


@dataclass(frozen=True)
class AssessableAsset:
    asset_id: str
    ip_address: str
    asset_category: str = "IOT_DEVICE"  # "IOT_DEVICE" | "IOT_INFRASTRUCTURE"
    asset_type: str = "ESP32"           # "ESP32", "MQTT_BROKER", "GATEWAY", etc.
    subtype: str | None = None
    status: str = "UNKNOWN"
    mac_address: str | None = None
    firmware_version: str | None = None


# Backward-compatible alias
AssessableDevice = AssessableAsset


def get_authorized_iot_assets(
    db: Session,
    settings: Settings,
    asset_ids: list[str] | None = None,
) -> list[AssessableAsset]:
    """Return discovered and configured IoT assets that are explicitly in ASSESSMENT_ALLOWED_TARGETS.

    Discovery != Authorization:
    An asset must exist in the device inventory or infrastructure configuration
    AND its current IP address must be present in the explicit allowlist.

    Classifies assets into:
    - IOT_DEVICE: Physical IoT devices (e.g. ESP32-01, ESP32-02, DHT22 nodes)
    - IOT_INFRASTRUCTURE: IoT infrastructure hosts (e.g. MQTT Broker, Gateways)
    """
    allowed_ips = parse_allowed_targets(settings.assessment_allowed_targets)
    assessable_by_id: dict[str, AssessableAsset] = {}

    # 1. Discovered devices from inventory table
    inventory = list_devices(db)
    for dev in inventory:
        if not dev.ip_address:
            continue
        try:
            addr = ip_address(dev.ip_address.strip())
        except ValueError:
            continue

        if addr in allowed_ips:
            dev_type = (dev.device_type or "ESP32").strip()
            dtype_upper = dev_type.upper()
            is_infra = dtype_upper in INFRASTRUCTURE_TYPES or dtype_upper.startswith("INFRA_")
            category = "IOT_INFRASTRUCTURE" if is_infra else "IOT_DEVICE"
            assessable_by_id[dev.device_id] = AssessableAsset(
                asset_id=dev.device_id,
                ip_address=str(addr),
                asset_category=category,
                asset_type=dev_type,
                subtype=dev_type if is_infra else None,
                status=dev.status,
                mac_address=dev.mac_address,
                firmware_version=dev.firmware_version,
            )

    # 2. Configured IoT Infrastructure: MQTT Broker
    if settings.mqtt_broker_host:
        try:
            broker_host = settings.mqtt_broker_host.strip()
            resolved_ip = socket.gethostbyname(broker_host)
            broker_addr = ip_address(resolved_ip)
            if broker_addr in allowed_ips:
                broker_id = "MQTT-BROKER"
                if broker_id not in assessable_by_id:
                    assessable_by_id[broker_id] = AssessableAsset(
                        asset_id=broker_id,
                        ip_address=str(broker_addr),
                        asset_category="IOT_INFRASTRUCTURE",
                        asset_type="MQTT_BROKER",
                        subtype="MQTT_BROKER",
                        status="ONLINE",
                    )
        except Exception as exc:
            logger.warning(
                "Could not resolve or authorize configured MQTT broker '%s': %s",
                settings.mqtt_broker_host,
                exc,
            )

    if asset_ids is not None:
        selected: list[AssessableAsset] = []
        for requested_id in asset_ids:
            match = assessable_by_id.get(requested_id)
            if not match:
                for asset in assessable_by_id.values():
                    if asset.ip_address == requested_id:
                        match = asset
                        break
            if not match:
                raise TargetNotAllowedError(
                    f"Requested asset '{requested_id}' is not an explicitly authorized assessment target."
                )
            selected.append(match)
        return selected

    return list(assessable_by_id.values())


# Backward-compatible function name
def get_assessable_devices(
    db: Session,
    settings: Settings,
    device_ids: list[str] | None = None,
) -> list[AssessableAsset]:
    return get_authorized_iot_assets(db, settings, asset_ids=device_ids)


def run_environment_assessment(
    db: Session,
    settings: Settings,
    *,
    device_ids: list[str] | None = None,
    probes: AssessmentProbes = DEFAULT_PROBES,
) -> AssessmentDetailOut:
    """Assess all explicitly authorized IoT assets (devices and infrastructure) independently,
    then aggregate into an overall environment security posture."""
    assessable = get_authorized_iot_assets(db, settings, asset_ids=device_ids)
    if not assessable:
        raise TargetNotAllowedError(
            "No authorized IoT assets are currently available for assessment."
        )

    batch_id = uuid4()
    batch_started_at = _utc_now()
    logger.info(
        "Starting environment assessment batch %s for %d authorized asset(s)",
        batch_id,
        len(assessable),
    )

    asset_runs: list[tuple[AssessableAsset, AssessmentDetailOut]] = []
    for asset in assessable:
        # Strictly enforce allowlist boundary for each asset IP
        validate_target(asset.ip_address, settings.assessment_allowed_targets)

        detail = run_assessment(
            db,
            settings,
            asset.ip_address,
            probes=probes,
            metadata_extra={
                "batch_id": str(batch_id),
                "asset_id": asset.asset_id,
                "asset_category": asset.asset_category,
                "asset_type": asset.asset_type,
                "subtype": asset.subtype,
                "device_id": asset.asset_id,
                "device_type": asset.asset_type,
                "scope": "AUTHORIZED_IOT",
            },
        )
        asset_runs.append((asset, detail))

    assets_assessed = len(assessable)
    completed_runs = [(asset, run) for asset, run in asset_runs if run.status == "COMPLETE"]
    assets_completed = len(completed_runs)
    assets_failed = assets_assessed - assets_completed

    devices_assessed = sum(1 for a, _ in asset_runs if a.asset_category == "IOT_DEVICE")
    devices_completed = sum(1 for a, r in completed_runs if a.asset_category == "IOT_DEVICE")
    devices_failed = devices_assessed - devices_completed

    infrastructure_assessed = sum(1 for a, _ in asset_runs if a.asset_category == "IOT_INFRASTRUCTURE")
    infrastructure_completed = sum(1 for a, r in completed_runs if a.asset_category == "IOT_INFRASTRUCTURE")
    infrastructure_failed = infrastructure_assessed - infrastructure_completed

    # Derive overall posture without synthetic or invented scores
    highest_risk: float | None = None
    highest_risk_asset: str | None = None
    for asset, run in completed_runs:
        if run.highest_risk is not None:
            if highest_risk is None or run.highest_risk > highest_risk:
                highest_risk = run.highest_risk
                highest_risk_asset = asset.asset_id

    overall_risk_level: str | None = None
    best_rank = 0
    for _, run in completed_runs:
        level = (run.highest_risk_level or "").upper()
        rank = SEVERITY_RANK.get(level, 0)
        if rank > best_rank:
            best_rank = rank
            overall_risk_level = level

    total_findings = sum(len(run.findings) for _, run in asset_runs)
    important_findings = sum(
        1
        for _, run in asset_runs
        for f in run.findings
        if f.severity.upper() in ("CRITICAL", "HIGH", "MEDIUM")
    )
    additional_findings = sum(
        1
        for _, run in asset_runs
        for f in run.findings
        if f.severity.upper() in ("LOW", "INFO")
    )

    if assets_failed == 0 and assets_completed > 0:
        batch_status = "COMPLETE"
        error_summary = None
    elif assets_completed == 0:
        batch_status = "FAILED"
        error_summary = "All asset assessments in the environment failed."
    else:
        batch_status = "INCOMPLETE"
        error_summary = (
            f"{assets_completed} of {assets_assessed} assets assessed successfully; "
            f"{assets_failed} asset assessment(s) failed."
        )

    asset_runs_summary = [
        {
            "asset_id": asset.asset_id,
            "asset_category": asset.asset_category,
            "asset_type": asset.asset_type,
            "subtype": asset.subtype,
            "device_id": asset.asset_id,
            "device_type": asset.asset_type,
            "target": asset.ip_address,
            "ip_address": asset.ip_address,
            "assessment_id": str(run.id),
            "status": run.status,
            "highest_risk": run.highest_risk,
            "highest_risk_level": run.highest_risk_level,
            "finding_count": len(run.findings),
            "findings_count": len(run.findings),
            "error_summary": run.error_summary,
            "status_telemetry": asset.status,
        }
        for asset, run in asset_runs
    ]
    device_summaries = [s for s in asset_runs_summary if s["asset_category"] == "IOT_DEVICE"]
    infrastructure_summaries = [s for s in asset_runs_summary if s["asset_category"] == "IOT_INFRASTRUCTURE"]

    posture = {
        "batch_id": str(batch_id),
        "assessed_at": batch_started_at.isoformat(),
        "overall_risk_score": highest_risk,
        "overall_risk_level": overall_risk_level,
        "highest_risk_asset": highest_risk_asset,
        "highest_device_risk": highest_risk,
        "highest_device_id": highest_risk_asset,
        "highest_risk_device": highest_risk_asset,
        "assets_assessed": assets_assessed,
        "assets_completed": assets_completed,
        "assets_failed": assets_failed,
        "devices_assessed": devices_assessed,
        "devices_completed": devices_completed,
        "devices_failed": devices_failed,
        "infrastructure_assessed": infrastructure_assessed,
        "infrastructure_completed": infrastructure_completed,
        "infrastructure_failed": infrastructure_failed,
        "total_findings": total_findings,
        "important_findings": important_findings,
        "additional_findings": additional_findings,
        "asset_summaries": asset_runs_summary,
        "device_summaries": device_summaries,
        "infrastructure_summaries": infrastructure_summaries,
    }

    completed_at = _utc_now()

    # Synchronize child runs' started_at with batch_started_at to prevent timestamp inversion
    child_ids = [run.id for _, run in asset_runs]
    if child_ids:
        db.execute(
            text(
                """
                UPDATE assessment_runs
                SET started_at = :batch_started_at
                WHERE id = ANY(:child_ids)
                """
            ),
            {"batch_started_at": batch_started_at, "child_ids": child_ids},
        )

    checks_evaluated = []
    for _, run in asset_runs:
        child_cov = (run.metadata or {}).get("checks_evaluated", [])
        if isinstance(child_cov, list):
            checks_evaluated.extend(child_cov)

    # Persist aggregate environment run in assessment_runs
    db.execute(
        text(
            """
            INSERT INTO assessment_runs
                (id, target, status, assessment_type, started_at, completed_at, error_summary, metadata)
            VALUES
                (:id, 'AUTHORIZED_IOT', :status, 'ENVIRONMENT', :started_at, :completed_at, :error_summary, CAST(:metadata AS jsonb))
            """
        ),
        {
            "id": batch_id,
            "status": batch_status,
            "started_at": batch_started_at,
            "completed_at": completed_at,
            "error_summary": error_summary,
            "metadata": _json(
                {
                    "scope": "AUTHORIZED_IOT",
                    "batch_id": str(batch_id),
                    "posture": posture,
                    "asset_runs": asset_runs_summary,
                    "device_runs": device_summaries,
                    "infrastructure_runs": infrastructure_summaries,
                    "checks_evaluated": checks_evaluated,
                }
            ),
        },
    )

    # Persist findings and evidence under batch_id for unified querying, preserving true target/port ownership.
    # Build a mapping from child evidence UUIDs to new parent evidence UUIDs so that
    # evidence_reference on findings and finding_ref on risk_snapshots can be remapped.
    child_to_parent_evidence: dict[str, str] = {}
    child_to_parent_finding: dict[str, str] = {}

    for _, run in asset_runs:
        for ev in run.evidence:
            new_ev_id = db.execute(
                text(
                    """
                    INSERT INTO assessment_evidence
                        (id, assessment_id, target, port, check_type, result,
                         evidence_source, observation, observed_at)
                    VALUES
                        (gen_random_uuid(), :assessment_id, :target, :port, :check_type, :result,
                         :evidence_source, CAST(:observation AS jsonb), :observed_at)
                    RETURNING id
                    """
                ),
                {
                    "assessment_id": batch_id,
                    "target": ev.target,
                    "port": ev.port,
                    "check_type": ev.check_type,
                    "result": ev.result,
                    "evidence_source": ev.evidence_source,
                    "observation": _json(ev.observation),
                    "observed_at": ev.observed_at,
                },
            ).scalar_one()
            child_to_parent_evidence[str(ev.id)] = str(new_ev_id)

        for f in run.findings:
            # Remap evidence_reference from child evidence UUID to new parent evidence UUID
            remapped_evidence_ref = None
            if f.evidence_reference:
                remapped_evidence_ref = child_to_parent_evidence.get(
                    str(f.evidence_reference), str(f.evidence_reference)
                )

            new_finding_id = db.execute(
                text(
                    """
                    INSERT INTO assessment_findings
                        (id, assessment_id, finding_id, finding_type, category, title,
                         severity, confidence, description, target, port,
                         evidence_reference, remediation, status, created_at)
                    VALUES
                        (gen_random_uuid(), :assessment_id, :finding_id, :finding_type, :category, :title,
                         :severity, :confidence, :description, :target, :port,
                         :evidence_reference, :remediation, :status, :created_at)
                    RETURNING id
                    """
                ),
                {
                    "assessment_id": batch_id,
                    "finding_id": f.finding_id,
                    "finding_type": f.finding_type,
                    "category": f.category,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                    "target": f.target,
                    "port": f.port,
                    "evidence_reference": remapped_evidence_ref,
                    "remediation": f.remediation,
                    "status": f.status,
                    "created_at": f.created_at,
                },
            ).scalar_one()
            child_to_parent_finding[str(f.id)] = str(new_finding_id)

        # Duplicate per-finding risk snapshots from child runs, remapping finding_ref
        for snap in run.risk_snapshots:
            if snap.finding_ref is None:
                # Skip the child's overall snapshot — we insert our own below
                continue
            remapped_finding_ref = child_to_parent_finding.get(
                str(snap.finding_ref), str(snap.finding_ref)
            )
            db.execute(
                text(
                    """
                    INSERT INTO risk_snapshots
                        (id, assessment_id, finding_ref, score, risk_level, score_version,
                         base_severity, context_score, factor_contributions, context_inputs)
                    VALUES
                        (gen_random_uuid(), :assessment_id, :finding_ref, :score, :risk_level,
                         :score_version, :base_severity, :context_score,
                         CAST(:factor_contributions AS jsonb), CAST(:context_inputs AS jsonb))
                    """
                ),
                {
                    "assessment_id": batch_id,
                    "finding_ref": remapped_finding_ref,
                    "score": snap.score,
                    "risk_level": snap.risk_level,
                    "score_version": snap.score_version,
                    "base_severity": snap.base_severity,
                    "context_score": snap.context_score,
                    "factor_contributions": _json(snap.factor_contributions),
                    "context_inputs": _json(snap.context_inputs),
                },
            )

    # Insert overall risk snapshot for the environment run only if a genuine risk calculation occurred
    if highest_risk is not None and overall_risk_level is not None:
        db.execute(
            text(
                """
                INSERT INTO risk_snapshots
                    (id, assessment_id, finding_ref, score, risk_level, score_version, context_inputs)
                VALUES
                    (gen_random_uuid(), :assessment_id, NULL, :score, :risk_level, 'IoT-RISK-v1', CAST(:context_inputs AS jsonb))
                """
            ),
            {
                "assessment_id": batch_id,
                "score": highest_risk,
                "risk_level": overall_risk_level,
                "context_inputs": _json(
                    {
                        "overall_posture": True,
                        "assets_assessed": assets_assessed,
                        "devices_assessed": devices_assessed,
                        "infrastructure_assessed": infrastructure_assessed,
                        "highest_risk_asset": highest_risk_asset,
                    }
                ),
            },
        )
    db.commit()

    detail = get_assessment(db, batch_id)
    if detail is None:
        raise RuntimeError("Failed to load newly created environment assessment")
    return detail
