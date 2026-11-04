"""
UX-3D: read-only finding -> risk factor trace. The trace only joins recorded
IDs with the same IoT-RISK-v1 rules _risk_context uses; it never scores.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.schemas.assessment import (
    AssessmentEvidenceOut,
    AssessmentFindingOut,
    RiskSnapshotOut,
    RiskTraceFactorOut,
    RiskTraceOut,
)
from app.services import assessment_service, risk_trace
from app.services.risk_trace import build_risk_trace
from risk_engine.rules.risk_rules import RISK_SCORE_VERSION

RUN = uuid.uuid4()
TARGET = "127.0.0.250"
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)


def evidence(check_type: str, result: str, port: int | None, source: str) -> AssessmentEvidenceOut:
    return AssessmentEvidenceOut(
        id=uuid.uuid4(), assessment_id=RUN, target=TARGET, port=port,
        check_type=check_type, result=result, evidence_source=source,
        observation={}, observed_at=T0,
    )


def finding(check: str, finding_type: str, severity: str, port: int | None,
            ref: AssessmentEvidenceOut | None) -> AssessmentFindingOut:
    return AssessmentFindingOut(
        id=uuid.uuid4(), assessment_id=RUN, finding_id=check, finding_type=finding_type,
        category="X", title=check, severity=severity, confidence=0.9, description=None,
        target=TARGET, port=port, evidence_reference=ref.id if ref else None,
        remediation=None, status="OPEN", created_at=T0,
    )


def snapshot(ref: AssessmentFindingOut | None, score: float, level: str,
             version: str = "IoT-RISK-v1", at: datetime = T0) -> RiskSnapshotOut:
    return RiskSnapshotOut(
        id=uuid.uuid4(), assessment_id=RUN, finding_ref=ref.id if ref else None,
        score=score, risk_level=level, score_version=version, base_severity="HIGH",
        context_score=0.66, factor_contributions={}, context_inputs={}, created_at=at,
    )


def recorded_run():
    """Shape of the real latest assessment (4c6fcd59): 7 evidence, 7 findings."""
    scan = evidence("NMAP_SCAN", "RESPONDED", None, "NMAP")
    port = {p: evidence("NMAP_PORT", "OPEN", p, "NMAP") for p in (139, 445, 1883)}
    anon_ev = evidence("MQTT_ANONYMOUS_CONNECT", "ACCEPTED", 1883, "MQTT_PROBE")
    plain_ev = evidence("MQTT_TRANSPORT_COMPARISON", "PLAINTEXT_NO_TLS", 1883, "MQTT_PROBE")
    tls_ev = evidence("TLS_HANDSHAKE", "REFUSED", 8883, "TLS_PROBE")
    anon = finding("IOT-MQTT-01", "MQTT_ANONYMOUS_ACCESS", "HIGH", 1883, anon_ev)
    plain = finding("IOT-MQTT-02", "MQTT_WITHOUT_TLS", "MEDIUM", 1883, plain_ev)
    net01 = [finding("NET-01", "OPEN_TCP_SERVICE", "INFO", p, port[p]) for p in (445, 139, 1883)]
    net06 = [finding("NET-06", "ADMIN_SERVICE_EXPOSED", "LOW", p, port[p]) for p in (445, 139)]
    findings = [anon, plain, *net01, *net06]
    snapshots = [
        snapshot(anon, 70.5, "HIGH"),
        snapshot(plain, 58.0, "MEDIUM"),
        *(snapshot(f, 45.5, "MEDIUM") for f in net06),
        snapshot(None, 70.5, "HIGH"),
    ]
    ev = [scan, *port.values(), anon_ev, plain_ev, tls_ev]
    return SimpleNamespace(ev=ev, findings=findings, snapshots=snapshots, anon=anon,
                           plain=plain, net01=net01, net06=net06, port=port,
                           anon_ev=anon_ev, plain_ev=plain_ev)


def by_factor(trace: RiskTraceOut) -> dict[str, RiskTraceFactorOut]:
    return {factor.factor: factor for factor in trace.factors}


def test_trace_links_recorded_findings_to_factors_by_backend_rules() -> None:
    run = recorded_run()
    trace = build_risk_trace(run.ev, run.findings, run.snapshots)
    assert trace is not None and trace.score_version == "IoT-RISK-v1"
    factors = by_factor(trace)
    assert set(factors) == {
        "authentication_security", "protocol_security", "network_exposure",
        "device_criticality", "firmware_security",
    }
    auth = factors["authentication_security"]
    assert auth.rule == "FINDING_TYPE"
    assert auth.finding_refs == [run.anon.id] and auth.evidence_refs == [run.anon_ev.id]
    proto = factors["protocol_security"]
    assert proto.finding_refs == [run.plain.id] and proto.evidence_refs == [run.plain_ev.id]
    exposure = factors["network_exposure"]
    assert exposure.rule == "OPEN_PORT_EVIDENCE"
    assert set(exposure.evidence_refs) == {e.id for e in run.port.values()}
    assert set(exposure.finding_refs) == {f.id for f in run.net01 + run.net06}
    for name in ("device_criticality", "firmware_security"):
        assert factors[name].rule == "CONFIGURATION"
        assert factors[name].finding_refs == [] and factors[name].evidence_refs == []


def test_trace_uses_recorded_ids_not_titles_or_sources() -> None:
    run = recorded_run()
    # Same MQTT_PROBE source as the anonymous finding, but a different type:
    # it must not be linked to authentication.
    trace = build_risk_trace(run.ev, run.findings, run.snapshots)
    auth = by_factor(trace)["authentication_security"]
    assert run.plain.id not in auth.finding_refs
    renamed = run.anon.model_copy(update={"title": "Something unrelated"})
    trace = build_risk_trace(run.ev, [renamed, *run.findings[1:]], run.snapshots)
    assert by_factor(trace)["authentication_security"].finding_refs == [renamed.id]


def test_overall_risk_points_to_the_highest_finding_snapshot() -> None:
    run = recorded_run()
    trace = build_risk_trace(run.ev, run.findings, run.snapshots)
    assert trace.overall_rule == "HIGHEST_FINDING_RISK"
    assert trace.overall_finding_refs == [run.anon.id]


def test_finding_without_evidence_reference_has_no_invented_evidence() -> None:
    run = recorded_run()
    orphan = finding("IOT-MQTT-01", "MQTT_ANONYMOUS_ACCESS", "HIGH", 1883, None)
    trace = build_risk_trace(run.ev, [orphan], [snapshot(orphan, 70.5, "HIGH"), snapshot(None, 70.5, "HIGH")])
    auth = by_factor(trace)["authentication_security"]
    assert auth.finding_refs == [orphan.id] and auth.evidence_refs == []
    assert by_factor(trace)["network_exposure"].finding_refs == []


def test_trace_contains_ids_and_rule_names_only() -> None:
    assert set(RiskTraceOut.model_fields) == {
        "score_version", "overall_rule", "overall_finding_refs", "factors",
    }
    assert set(RiskTraceFactorOut.model_fields) == {
        "factor", "rule", "finding_refs", "evidence_refs",
    }


@pytest.mark.parametrize("case", ["no_snapshots", "finding_only", "legacy_version"])
def test_trace_unavailable_without_a_current_overall_snapshot(case) -> None:
    run = recorded_run()
    snapshots = {
        "no_snapshots": [],
        "finding_only": [s for s in run.snapshots if s.finding_ref is not None],
        "legacy_version": [snapshot(None, 70.5, "HIGH", version="IoT-RISK-v0")],
    }[case]
    assert build_risk_trace(run.ev, run.findings, snapshots) is None


def test_trace_follows_the_newest_overall_snapshot() -> None:
    run = recorded_run()
    older = snapshot(None, 70.5, "HIGH", version="IoT-RISK-v0", at=T0 - timedelta(days=1))
    assert build_risk_trace(run.ev, run.findings, [older, *run.snapshots]) is not None


def test_trace_version_matches_the_risk_engine() -> None:
    assert risk_trace.TRACE_SCORE_VERSION == RISK_SCORE_VERSION


def test_risk_context_uses_the_shared_rule_sets() -> None:
    assert assessment_service.AUTHENTICATION_FINDING_TYPES is risk_trace.AUTHENTICATION_FINDING_TYPES
    assert assessment_service.PROTOCOL_FINDING_TYPES is risk_trace.PROTOCOL_FINDING_TYPES
    assert risk_trace.AUTHENTICATION_FINDING_TYPES == {"MQTT_ANONYMOUS_ACCESS"}
    assert risk_trace.PROTOCOL_FINDING_TYPES == {
        "MQTT_WITHOUT_TLS", "HTTP_PLAINTEXT", "OUTDATED_TLS_VERSION",
    }


@pytest.mark.parametrize(
    ("finding_types", "auth", "protocol"),
    [
        (set(), 0.0, 0.0),
        ({"MQTT_ANONYMOUS_ACCESS"}, 1.0, 0.0),
        ({"MQTT_WITHOUT_TLS"}, 0.0, 1.0),
        ({"HTTP_PLAINTEXT"}, 0.0, 1.0),
        ({"OUTDATED_TLS_VERSION"}, 0.0, 1.0),
        ({"MQTT_ANONYMOUS_ACCESS", "MQTT_WITHOUT_TLS"}, 1.0, 1.0),
        ({"OPEN_TCP_SERVICE"}, 0.0, 0.0),
    ],
)
def test_risk_context_behaviour_is_unchanged(finding_types, auth, protocol) -> None:
    settings = Settings(_env_file=None, ASSESSMENT_ALLOWED_TARGETS=TARGET,
                        ASSESSMENT_MAX_OPEN_SERVICES=5)
    scan = SimpleNamespace(open_ports=[object(), object(), object()])
    findings = [SimpleNamespace(finding_type=t, finding_id="X-01") for t in finding_types]
    _, provenance = assessment_service._risk_context(settings, scan, findings)
    assert provenance["authentication_security"]["value"] == auth
    assert provenance["protocol_security"]["value"] == protocol
    assert provenance["network_exposure"]["value"] == 0.6
