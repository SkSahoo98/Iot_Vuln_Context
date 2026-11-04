"""Tests for Milestone 2: Remediation Lifecycle, Verification Engine, and Comparison."""

from __future__ import annotations

from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import get_db
from app.main import app
from app.schemas.remediation import (
    RemediationConfirmRequest,
    RemediationVerifyRequest,
    RemediationWorkflowCreate,
)
from app.services.assessment_service import AssessmentProbes, run_assessment
from app.services.remediation_service import (
    confirm_remediation,
    create_or_get_remediation,
    get_remediation,
    get_remediation_comparison,
    list_remediations,
    make_finding_fingerprint,
    verify_remediation,
)
from scanner.core.models import Evidence
from scanner.network_checks.nmap_scanner import NmapError, NmapScanResult, PortObservation
from scanner.targets import TargetNotAllowedError

TARGET = "10.84.237.85"


def _open_mqtt_scan(target: str, ports: list[int], **kwargs) -> NmapScanResult:
    return NmapScanResult(
        target=target,
        host_state="up",
        nmap_version="test",
        args="mocked",
        ports=[
            PortObservation(
                port=1883,
                protocol="tcp",
                state="open",
                reason="syn-ack",
                service_name="mqtt",
                product="Mosquitto 2.1.2",
            )
        ],
    )


def _closed_mqtt_scan(target: str, ports: list[int], **kwargs) -> NmapScanResult:
    return NmapScanResult(
        target=target,
        host_state="up",
        nmap_version="test",
        args="mocked",
        ports=[
            PortObservation(
                port=1883,
                protocol="tcp",
                state="closed",
                reason="conn-refused",
                service_name="mqtt",
            )
        ],
    )


def _unreachable_scan(target: str, ports: list[int], **kwargs) -> NmapScanResult:
    return NmapScanResult(
        target=target,
        host_state="down",
        nmap_version="test",
        args="mocked",
        ports=[],
        extraports={"filtered": len(ports)},
    )


def _failing_scan(target: str, ports: list[int], **kwargs) -> NmapScanResult:
    raise NmapError("Simulated scanner binary crash")


def _anonymous_accepted(target: str, port: int, timeout: float) -> Evidence:
    return Evidence(
        target=target,
        port=port,
        check_type="MQTT_ANONYMOUS_CONNECT",
        result="ACCEPTED",
        evidence_source="MQTT_PROBE",
        observation={"connection_accepted": True, "reason_code": 0},
    )


def _anonymous_rejected(target: str, port: int, timeout: float) -> Evidence:
    return Evidence(
        target=target,
        port=port,
        check_type="MQTT_ANONYMOUS_CONNECT",
        result="REJECTED",
        evidence_source="MQTT_PROBE",
        observation={"connection_accepted": False, "reason_code": 5},
    )


def _tls_refused(target: str, port: int, timeout: float) -> Evidence:
    return Evidence(
        target=target,
        port=port,
        check_type="TLS_HANDSHAKE",
        result="REFUSED",
        evidence_source="TLS_PROBE",
        observation={"error_type": "ConnectionRefusedError"},
    )


def _tls_valid(target: str, port: int, timeout: float) -> Evidence:
    return Evidence(
        target=target,
        port=port,
        check_type="TLS_HANDSHAKE",
        result="ACCEPTED",
        evidence_source="TLS_PROBE",
        observation={"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
    )


def _create_baseline_run(db_session: Session, phase1_settings: Settings):
    baseline_probes = AssessmentProbes(
        nmap=_open_mqtt_scan,
        mqtt=_anonymous_accepted,
        tls=_tls_refused,
        http=lambda *a, **kw: None,
    )
    baseline = run_assessment(db_session, phase1_settings, TARGET, probes=baseline_probes)
    mqtt_finding = next(
        f for f in baseline.findings if f.finding_id == "IOT-MQTT-01" and f.port == 1883
    )
    return baseline, mqtt_finding


def test_remediation_lifecycle_states_and_confirmation(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)

    # 1. Create remediation workflow
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)
    assert wf.status == "OPEN"
    assert wf.baseline_assessment_id == baseline.id
    assert wf.baseline_finding_id == finding.id
    assert wf.target == TARGET
    assert wf.finding_fingerprint == make_finding_fingerprint(TARGET, "IOT-MQTT-01", 1883, finding.finding_type)
    assert wf.user_confirmed_at is None
    assert wf.verification_verdict is None

    # 2. Confirm remediation applied
    confirmed = confirm_remediation(
        db_session,
        wf.id,
        RemediationConfirmRequest(notes="Disabled allow_anonymous in mosquitto.conf"),
    )
    # MUST move to READY_FOR_VERIFICATION, NEVER VERIFIED_RESOLVED
    assert confirmed.status == "READY_FOR_VERIFICATION"
    assert confirmed.user_confirmed_at is not None
    assert confirmed.verification_verdict is None
    assert "user_confirmation_notes" in confirmed.coverage_summary

    # Ensure baseline assessment and finding remain immutable
    check_finding = db_session.execute(
        text("SELECT status FROM assessment_findings WHERE id = :id"),
        {"id": finding.id},
    ).scalar_one()
    assert check_finding == "OPEN"  # Baseline finding status is not overwritten


def test_remediation_requires_explicit_verification_approval(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)

    # Missing explicit approval must be rejected
    with pytest.raises(ValueError, match="Explicit user approval"):
        verify_remediation(
            db_session,
            phase1_settings,
            wf.id,
            RemediationVerifyRequest(explicit_approval=False),
        )


def test_verification_verdict_verified_resolved(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)
    confirm_remediation(db_session, wf.id, RemediationConfirmRequest())

    # Mock post-fix assessment: port 1883 open, but anonymous connection rejected
    resolved_probes = AssessmentProbes(
        nmap=_open_mqtt_scan,
        mqtt=_anonymous_rejected,
        tls=_tls_refused,
        http=lambda *a, **kw: None,
    )

    verified_wf = verify_remediation(
        db_session,
        phase1_settings,
        wf.id,
        RemediationVerifyRequest(explicit_approval=True),
        probes=resolved_probes,
    )

    assert verified_wf.status == "VERIFIED_RESOLVED"
    assert verified_wf.verification_verdict == "VERIFIED_RESOLVED"
    assert verified_wf.verification_assessment_id is not None
    assert verified_wf.verification_assessment_id != baseline.id
    assert len(verified_wf.verifications) == 1
    assert verified_wf.verifications[0].coverage_equivalent is True
    assert verified_wf.verifications[0].baseline_finding_present is False

    # Comparison check
    comp = get_remediation_comparison(db_session, wf.id)
    assert comp.verdict == "VERIFIED_RESOLVED"
    assert comp.coverage_equivalent is True
    assert comp.verification["finding_found"] is False


def test_verification_verdict_still_present(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)

    # Post-fix assessment still accepts anonymous connection
    still_present_probes = AssessmentProbes(
        nmap=_open_mqtt_scan,
        mqtt=_anonymous_accepted,
        tls=_tls_refused,
        http=lambda *a, **kw: None,
    )

    verified_wf = verify_remediation(
        db_session,
        phase1_settings,
        wf.id,
        RemediationVerifyRequest(explicit_approval=True),
        probes=still_present_probes,
    )

    assert verified_wf.status == "STILL_PRESENT"
    assert verified_wf.verification_verdict == "STILL_PRESENT"
    assert verified_wf.verifications[0].baseline_finding_present is True


def test_verification_verdict_inconclusive_when_unreachable(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)

    # Target went offline / unreachable
    offline_probes = AssessmentProbes(
        nmap=_unreachable_scan,
        mqtt=_anonymous_rejected,
        tls=_tls_refused,
        http=lambda *a, **kw: None,
    )

    verified_wf = verify_remediation(
        db_session,
        phase1_settings,
        wf.id,
        RemediationVerifyRequest(explicit_approval=True),
        probes=offline_probes,
    )

    # Must be INCONCLUSIVE, NEVER VERIFIED_RESOLVED
    assert verified_wf.status == "INCONCLUSIVE"
    assert verified_wf.verification_verdict == "INCONCLUSIVE"
    assert "did not respond" in (verified_wf.verdict_rationale or "").lower()


def test_verification_verdict_failed_on_scanner_crash(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)

    failing_probes = AssessmentProbes(
        nmap=_failing_scan,
        mqtt=_anonymous_rejected,
        tls=_tls_refused,
        http=lambda *a, **kw: None,
    )

    verified_wf = verify_remediation(
        db_session,
        phase1_settings,
        wf.id,
        RemediationVerifyRequest(explicit_approval=True),
        probes=failing_probes,
    )

    # Must be INCONCLUSIVE or VERIFICATION_FAILED (incomplete run), NEVER VERIFIED_RESOLVED
    assert verified_wf.verification_verdict in ("INCONCLUSIVE", "VERIFICATION_FAILED")


def test_remediation_api_routes(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)

    def _get_db():
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    try:
        client = TestClient(app)

        # 1. Create remediation
        resp = client.post(
            "/api/v1/remediations",
            json={
                "baseline_assessment_id": str(baseline.id),
                "baseline_finding_id": str(finding.id),
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        wf_id = data["id"]
        assert data["status"] == "OPEN"

        # 2. List remediations
        resp = client.get(f"/api/v1/remediations?baseline_assessment_id={baseline.id}")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

        # 3. Get remediation detail
        resp = client.get(f"/api/v1/remediations/{wf_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == wf_id

        # 4. Confirm fix applied
        resp = client.post(
            f"/api/v1/remediations/{wf_id}/confirm",
            json={"notes": "Updated config manually"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "READY_FOR_VERIFICATION"

        # 5. Non-existent finding returns 404
        bad_resp = client.post(
            "/api/v1/remediations",
            json={
                "baseline_assessment_id": str(baseline.id),
                "baseline_finding_id": str(uuid4()),
            },
        )
        assert bad_resp.status_code == 404
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_unauthorized_target_rejection(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)

    # Restrict allowed targets to exclude TARGET
    restricted_settings = Settings(
        _env_file=None,
        DATABASE_URL=phase1_settings.database_url,
        ASSESSMENT_ALLOWED_TARGETS="192.0.2.1",
        ASSESSMENT_PORTS="1883",
    )

    with pytest.raises(TargetNotAllowedError):
        verify_remediation(
            db_session,
            restricted_settings,
            wf.id,
            RemediationVerifyRequest(explicit_approval=True),
        )


def test_coverage_missing_yields_inconclusive(db_session: Session, phase1_settings: Settings):
    baseline, finding = _create_baseline_run(db_session, phase1_settings)
    wf = create_or_get_remediation(db_session, baseline.id, finding.id)

    # Verification run scanned port 80 only (never checked MQTT port 1883)
    def _http_only_scan(target: str, ports: list[int], **kwargs):
        return NmapScanResult(
            target=target,
            host_state="up",
            nmap_version="test",
            args="mocked",
            ports=[PortObservation(port=80, protocol="tcp", state="open", service_name="http")],
        )

    http_probes = AssessmentProbes(
        nmap=_http_only_scan,
        mqtt=lambda *a, **kw: None,
        tls=lambda *a, **kw: None,
        http=lambda target, port, scheme, timeout: Evidence(
            target=target, port=port, check_type="HTTP_RESPONSE", result="AVAILABLE", evidence_source="HTTP_PROBE", observation={"scheme": "http", "status_code": 200}
        ),
    )

    verified_wf = verify_remediation(
        db_session,
        phase1_settings,
        wf.id,
        RemediationVerifyRequest(explicit_approval=True),
        probes=http_probes,
    )

    # Must be INCONCLUSIVE because MQTT check was NOT_APPLICABLE / not evaluated
    assert verified_wf.verification_verdict == "INCONCLUSIVE"
    assert "coverage" in (verified_wf.verdict_rationale or "").lower()
