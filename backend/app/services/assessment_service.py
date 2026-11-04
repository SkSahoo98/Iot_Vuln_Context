"""Evidence-driven multi-layer assessment orchestration and persistence."""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.schemas.assessment import AssessmentDetailOut
from app.services.assessment_queries import (  # noqa: F401 - re-exported
    get_assessment,
    list_assessments,
)
from app.services.risk_trace import (
    AUTHENTICATION_FINDING_TYPES,
    PROTOCOL_FINDING_TYPES,
)

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from risk_engine.features.iot_context import build_mqtt_context  # noqa: E402
from risk_engine.scoring.dynamic_risk import calculate_dynamic_risk  # noqa: E402
from scanner.core.catalog import CHECK_CATALOG_VERSION  # noqa: E402
from scanner.core.coverage import (  # noqa: E402
    EVALUATED,
    MQTT_PREFIX,
    NETWORK_PREFIX,
    NOT_APPLICABLE,
    TLS_PREFIX,
    WEB_PREFIX,
    CheckCoverage,
    http_coverage,
    mqtt_coverage,
    tls_coverage,
)
from scanner.core.models import Evidence, FindingCandidate  # noqa: E402
from scanner.http_checks.http_probe import (  # noqa: E402
    evaluate_http,
    probe_http,
)
from scanner.mqtt_checks.mqtt_probe import probe_mqtt_anonymous  # noqa: E402
from scanner.mqtt_checks.mqtt_rules import evaluate_mqtt  # noqa: E402
from scanner.network_checks.network_rules import (  # noqa: E402
    evaluate_network,
    http_endpoints,
    tls_endpoints,
)
from scanner.network_checks.nmap_scanner import (  # noqa: E402
    NmapError,
    NmapScanResult,
    build_nmap_evidence,
    parse_port_list,
    run_nmap,
)
from scanner.targets import validate_target  # noqa: E402
from scanner.tls_checks.tls_probe import evaluate_tls, probe_tls  # noqa: E402

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AssessmentProbes:
    """Injectable external operations, allowing tests to run without a network."""

    nmap: Callable[..., NmapScanResult] = run_nmap
    mqtt: Callable[..., Evidence] = probe_mqtt_anonymous
    http: Callable[..., Evidence] = probe_http
    tls: Callable[..., Evidence] = probe_tls


DEFAULT_PROBES = AssessmentProbes()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _json(value: object) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def _parse_csv_ports(value: str) -> list[int]:
    return parse_port_list(value)


def _insert_run(
    db: Session,
    target: str,
    metadata: dict[str, object],
) -> UUID:
    run_id = db.execute(
        text(
            """
            INSERT INTO assessment_runs
                (target, status, assessment_type, metadata)
            VALUES
                (:target, 'RUNNING', 'MULTI_LAYER', CAST(:metadata AS jsonb))
            RETURNING id
            """
        ),
        {"target": target, "metadata": _json(metadata)},
    ).scalar_one()
    db.commit()
    return run_id


def _update_run(
    db: Session,
    assessment_id: UUID,
    status: str,
    error_summary: str | None,
    metadata_update: dict[str, object] | None = None,
) -> None:
    db.execute(
        text(
            """
            UPDATE assessment_runs
            SET status = :status,
                completed_at = :completed_at,
                error_summary = :error_summary,
                metadata = metadata || CAST(:metadata_update AS jsonb)
            WHERE id = :assessment_id
            """
        ),
        {
            "assessment_id": assessment_id,
            "status": status,
            "completed_at": _utc_now(),
            "error_summary": error_summary,
            "metadata_update": _json(metadata_update or {}),
        },
    )
    db.commit()


def _persist_evidence(
    db: Session,
    assessment_id: UUID,
    evidence: list[Evidence],
) -> None:
    for item in evidence:
        db.execute(
            text(
                """
                INSERT INTO assessment_evidence
                    (id, assessment_id, target, port, check_type, result,
                     evidence_source, observation, observed_at)
                VALUES
                    (:id, :assessment_id, :target, :port, :check_type, :result,
                     :evidence_source, CAST(:observation AS jsonb), :observed_at)
                ON CONFLICT (id) DO NOTHING
                """
            ),
            {
                "id": item.id,
                "assessment_id": assessment_id,
                "target": item.target,
                "port": item.port,
                "check_type": item.check_type,
                "result": item.result,
                "evidence_source": item.evidence_source,
                "observation": _json(item.observation),
                "observed_at": item.observed_at,
            },
        )
    db.commit()


def _persist_findings(
    db: Session,
    assessment_id: UUID,
    findings: list[FindingCandidate],
) -> dict[int, UUID]:
    """Persist findings and map their in-memory index to database UUID."""
    ids: dict[int, UUID] = {}
    for index, finding in enumerate(findings):
        finding_db_id = db.execute(
            text(
                """
                INSERT INTO assessment_findings
                    (assessment_id, finding_id, finding_type, category, title,
                     severity, confidence, description, target, port,
                     evidence_reference, remediation, status)
                VALUES
                    (:assessment_id, :finding_id, :finding_type, :category,
                     :title, :severity, :confidence, :description, :target,
                     :port, :evidence_reference, :remediation, 'OPEN')
                RETURNING id
                """
            ),
            {
                "assessment_id": assessment_id,
                "finding_id": finding.finding_id,
                "finding_type": finding.finding_type,
                "category": finding.category,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description,
                "target": finding.target,
                "port": finding.port,
                "evidence_reference": finding.evidence.id,
                "remediation": finding.remediation,
            },
        ).scalar_one()
        ids[index] = finding_db_id
    db.commit()
    return ids


def _risk_context(
    settings: Settings,
    scan: NmapScanResult,
    findings: list[FindingCandidate],
) -> tuple[object, dict[str, object]]:
    finding_types = {finding.finding_type for finding in findings}
    anonymous_observed = bool(finding_types & AUTHENTICATION_FINDING_TYPES)
    insecure_protocol_observed = bool(finding_types & PROTOCOL_FINDING_TYPES)
    threshold = max(1, settings.assessment_max_open_services)
    exposure = min(len(scan.open_ports) / threshold, 1.0)

    context = build_mqtt_context(
        device_criticality=settings.risk_device_criticality,
        network_exposure=exposure,
        anonymous_access=anonymous_observed,
        tls_enabled=not insecure_protocol_observed,
        firmware_security=settings.risk_firmware_security,
    )
    provenance: dict[str, object] = {
        "device_criticality": {
            "value": settings.risk_device_criticality,
            "source": "CONFIGURATION",
            "limitation": "Explicit contextual input; not inferred by this phase.",
        },
        "network_exposure": {
            "value": exposure,
            "source": "NMAP",
            "derivation": (
                f"min(open_ports={len(scan.open_ports)} / "
                f"threshold={threshold}, 1.0)"
            ),
        },
        "authentication_security": {
            "value": 1.0 if anonymous_observed else 0.0,
            "source": "MQTT_PROBE"
            if any(f.finding_id == "IOT-MQTT-01" for f in findings)
            else "NOT_ASSESSED_OR_NOT_OBSERVED",
        },
        "protocol_security": {
            "value": 1.0 if insecure_protocol_observed else 0.0,
            "source": "ACTIVE_PROBE"
            if insecure_protocol_observed
            else "NOT_ASSESSED_OR_NOT_OBSERVED",
        },
        "firmware_security": {
            "value": settings.risk_firmware_security,
            "source": "CONFIGURATION",
            "limitation": (
                "Existing IoT-RISK-v1 input; higher values mean higher risk."
            ),
        },
        "model_limitations": [
            "The current model can double-count a finding in context.",
            "Device criticality and firmware security remain configured inputs.",
            "A zero factor can mean not observed or not assessed in Phase 1.",
        ],
    }
    return context, provenance


def _persist_risk(
    db: Session,
    assessment_id: UUID,
    scan: NmapScanResult,
    findings: list[FindingCandidate],
    finding_ids: dict[int, UUID],
    settings: Settings,
) -> None:
    context, provenance = _risk_context(settings, scan, findings)
    results: list[tuple[UUID, object]] = []

    for index, finding in enumerate(findings):
        if finding.severity == "INFO":
            continue
        result = calculate_dynamic_risk(
            base_severity=finding.severity,
            context=context,  # type: ignore[arg-type]
        )
        results.append((finding_ids[index], result))
        db.execute(
            text(
                """
                INSERT INTO risk_snapshots
                    (assessment_id, finding_ref, score, risk_level,
                     score_version, base_severity, context_score,
                     factor_contributions, context_inputs)
                VALUES
                    (:assessment_id, :finding_ref, :score, :risk_level,
                     :score_version, :base_severity, :context_score,
                     CAST(:factor_contributions AS jsonb),
                     CAST(:context_inputs AS jsonb))
                """
            ),
            {
                "assessment_id": assessment_id,
                "finding_ref": finding_ids[index],
                "score": result.score,
                "risk_level": result.risk_level,
                "score_version": result.score_version,
                "base_severity": result.base_severity,
                "context_score": result.context_score,
                "factor_contributions": _json(result.factor_contributions),
                "context_inputs": _json(provenance),
            },
        )

    if results:
        _, highest = max(results, key=lambda item: item[1].score)  # type: ignore[union-attr]
        db.execute(
            text(
                """
                INSERT INTO risk_snapshots
                    (assessment_id, finding_ref, score, risk_level,
                     score_version, base_severity, context_score,
                     factor_contributions, context_inputs)
                VALUES
                    (:assessment_id, NULL, :score, :risk_level,
                     :score_version, :base_severity, :context_score,
                     CAST(:factor_contributions AS jsonb),
                     CAST(:context_inputs AS jsonb))
                """
            ),
            {
                "assessment_id": assessment_id,
                "score": highest.score,  # type: ignore[union-attr]
                "risk_level": highest.risk_level,  # type: ignore[union-attr]
                "score_version": highest.score_version,  # type: ignore[union-attr]
                "base_severity": highest.base_severity,  # type: ignore[union-attr]
                "context_score": highest.context_score,  # type: ignore[union-attr]
                "factor_contributions": _json(
                    highest.factor_contributions  # type: ignore[union-attr]
                ),
                "context_inputs": _json(provenance),
            },
        )
    db.commit()


def _append_finding_evidence(
    evidence: list[Evidence],
    findings: list[FindingCandidate],
) -> None:
    known = {item.id for item in evidence}
    for finding in findings:
        if finding.evidence.id not in known:
            evidence.append(finding.evidence)
            known.add(finding.evidence.id)


def run_assessment(
    db: Session,
    settings: Settings,
    requested_target: str,
    *,
    probes: AssessmentProbes = DEFAULT_PROBES,
    metadata_extra: dict[str, object] | None = None,
) -> AssessmentDetailOut:
    """Run and persist one synchronous assessment of one allowlisted target."""
    target = str(
        validate_target(requested_target, settings.assessment_allowed_targets)
    )
    ports = _parse_csv_ports(settings.assessment_ports)
    if settings.mqtt_broker_port not in ports:
        ports.append(settings.mqtt_broker_port)
    if settings.mqtt_tls_port not in ports:
        ports.append(settings.mqtt_tls_port)
    ports.sort()

    run_meta: dict[str, object] = {
        "ports": ports,
        "nmap_arguments": ["-sT", "-Pn", "-sV"],
        "nmap_timeout_seconds": settings.nmap_timeout_seconds,
        "probe_timeout_seconds": settings.assessment_probe_timeout_seconds,
        "open_service_threshold": settings.assessment_max_open_services,
        "mqtt_broker_port": settings.mqtt_broker_port,
        "mqtt_tls_port": settings.mqtt_tls_port,
        "check_catalog_version": CHECK_CATALOG_VERSION,
    }
    if metadata_extra:
        run_meta.update(metadata_extra)

    assessment_id = _insert_run(
        db,
        target,
        run_meta,
    )

    evidence: list[Evidence] = []
    findings: list[FindingCandidate] = []
    incomplete_reasons: list[str] = []
    coverage = CheckCoverage()
    metadata_update: dict[str, object] = {}

    def completion_metadata() -> dict[str, object]:
        return {**metadata_update, "checks_evaluated": coverage.to_metadata()}

    try:
        try:
            scan = probes.nmap(
                target,
                ports,
                nmap_path=settings.nmap_path,
                timeout_seconds=settings.nmap_timeout_seconds,
            )
        except NmapError as exc:
            evidence.append(
                Evidence(
                    target=target,
                    check_type="NMAP_SCAN",
                    result="ERROR",
                    evidence_source="NMAP",
                    observation={
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:500],
                    },
                )
            )
            _persist_evidence(db, assessment_id, evidence)
            _update_run(
                db,
                assessment_id,
                "INCOMPLETE",
                f"Network discovery could not be completed: {exc}",
                completion_metadata(),
            )
            return get_assessment(db, assessment_id)

        summary_evidence, port_evidence = build_nmap_evidence(scan)
        evidence.extend([summary_evidence, *port_evidence.values()])

        if not scan.target_responded:
            _persist_evidence(db, assessment_id, evidence)
            _update_run(
                db,
                assessment_id,
                "INCOMPLETE",
                (
                    "The target did not respond on the limited assessment port "
                    "set; security findings could not be verified."
                ),
                completion_metadata(),
            )
            return get_assessment(db, assessment_id)

        admin_ports = _parse_csv_ports(settings.assessment_admin_service_ports)
        metadata_update["admin_service_ports"] = admin_ports
        findings.extend(
            evaluate_network(
                scan,
                summary_evidence,
                port_evidence,
                max_open_services=settings.assessment_max_open_services,
                admin_service_ports=admin_ports,
            )
        )
        coverage.record_family(NETWORK_PREFIX, EVALUATED, None)

        tls_observations: dict[int, Evidence] = {}
        mqtt_open = any(
            item.port == settings.mqtt_broker_port
            or (item.service_name or "").lower() == "mqtt"
            for item in scan.open_ports
        )
        if mqtt_open:
            mqtt_evidence = probes.mqtt(
                target,
                settings.mqtt_broker_port,
                timeout=settings.assessment_probe_timeout_seconds,
            )
            mqtt_tls_evidence = probes.tls(
                target,
                settings.mqtt_tls_port,
                timeout=settings.assessment_probe_timeout_seconds,
            )
            tls_observations[settings.mqtt_tls_port] = mqtt_tls_evidence
            evidence.extend([mqtt_evidence, mqtt_tls_evidence])
            mqtt_findings = evaluate_mqtt(mqtt_evidence, mqtt_tls_evidence)
            findings.extend(mqtt_findings)
            _append_finding_evidence(evidence, mqtt_findings)
            coverage.record(
                mqtt_coverage(mqtt_evidence, mqtt_tls_evidence),
                settings.mqtt_broker_port,
            )
            if mqtt_evidence.result not in {"ACCEPTED", "REJECTED"}:
                incomplete_reasons.append(
                    "The MQTT listener was observed but the MQTT CONNECT check "
                    f"returned {mqtt_evidence.result}."
                )
        else:
            coverage.record_family(
                MQTT_PREFIX, NOT_APPLICABLE, settings.mqtt_broker_port
            )

        endpoints = http_endpoints(scan)
        http_evidence: list[Evidence] = []
        for port, scheme in endpoints:
            item = probes.http(
                target,
                port,
                scheme,
                timeout=settings.assessment_probe_timeout_seconds,
            )
            evidence.append(item)
            http_evidence.append(item)
            if item.result != "AVAILABLE":
                incomplete_reasons.append(
                    f"HTTP check on {target}:{port} returned {item.result}."
                )

        https_available = any(
            item.result == "AVAILABLE"
            and item.observation.get("scheme") == "https"
            for item in http_evidence
        )
        for item in http_evidence:
            findings.extend(
                evaluate_http(item, https_available=https_available)
            )
            coverage.record(http_coverage(item), item.port)
        if not endpoints:
            coverage.record_family(WEB_PREFIX, NOT_APPLICABLE, None)

        checked_tls_ports = tls_endpoints(scan, settings.mqtt_tls_port)
        for port in checked_tls_ports:
            if port not in tls_observations:
                tls_observations[port] = probes.tls(
                    target,
                    port,
                    timeout=settings.assessment_probe_timeout_seconds,
                )
                evidence.append(tls_observations[port])
            tls_evidence = tls_observations[port]
            findings.extend(evaluate_tls(tls_evidence))
            coverage.record(tls_coverage(tls_evidence), port)
            if tls_evidence.result != "AVAILABLE":
                incomplete_reasons.append(
                    f"TLS check on {target}:{port} returned {tls_evidence.result}."
                )
        if not checked_tls_ports:
            coverage.record_family(TLS_PREFIX, NOT_APPLICABLE, None)

        _append_finding_evidence(evidence, findings)
        _persist_evidence(db, assessment_id, evidence)
        finding_ids = _persist_findings(db, assessment_id, findings)
        _persist_risk(
            db,
            assessment_id,
            scan,
            findings,
            finding_ids,
            settings,
        )

        status = "INCOMPLETE" if incomplete_reasons else "COMPLETE"
        _update_run(
            db,
            assessment_id,
            status,
            " ".join(incomplete_reasons) if incomplete_reasons else None,
            completion_metadata(),
        )
    except Exception as exc:
        logger.exception("Assessment %s failed", assessment_id)
        db.rollback()
        # Results recorded before the failure may not have been persisted.
        _update_run(
            db,
            assessment_id,
            "FAILED",
            f"{type(exc).__name__}: {str(exc)[:500]}",
            {"checks_evaluated": CheckCoverage().to_metadata()},
        )

    return get_assessment(db, assessment_id)
