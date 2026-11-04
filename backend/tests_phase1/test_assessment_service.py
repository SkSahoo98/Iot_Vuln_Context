from __future__ import annotations

from sqlalchemy import text

from app.services.assessment_service import AssessmentProbes, run_assessment
from scanner.core.models import Evidence
from scanner.network_checks.nmap_scanner import NmapScanResult, PortObservation

TARGET = "10.84.237.85"


def _mqtt_evidence(target: str, port: int, timeout: float) -> Evidence:
    return Evidence(
        target=target,
        port=port,
        check_type="MQTT_ANONYMOUS_CONNECT",
        result="ACCEPTED",
        evidence_source="MQTT_PROBE",
        observation={
            "connection_accepted": True,
            "reason_code": 0,
            "broker_version": None,
        },
    )


def _tls_unavailable(target: str, port: int, timeout: float) -> Evidence:
    return Evidence(
        target=target,
        port=port,
        check_type="TLS_HANDSHAKE",
        result="REFUSED",
        evidence_source="TLS_PROBE",
        observation={"error_type": "ConnectionRefusedError"},
    )


def _unexpected_http(*args, **kwargs):
    raise AssertionError("HTTP probe should not run in this scenario")


def _mqtt_scan(
    target: str,
    ports: list[int],
    *,
    nmap_path: str,
    timeout_seconds: int,
) -> NmapScanResult:
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
                product="Observed test broker",
            )
        ],
    )


def _no_response_scan(
    target: str,
    ports: list[int],
    *,
    nmap_path: str,
    timeout_seconds: int,
) -> NmapScanResult:
    return NmapScanResult(
        target=target,
        host_state="up",  # -Pn assumption is not treated as reachability proof
        nmap_version="test",
        args="mocked",
        ports=[],
        extraports={"filtered": len(ports)},
    )


def _closed_port_scan(
    target: str,
    ports: list[int],
    *,
    nmap_path: str,
    timeout_seconds: int,
) -> NmapScanResult:
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


def test_assessment_persists_evidence_findings_and_risk(
    db_session,
    phase1_settings,
) -> None:
    probes = AssessmentProbes(
        nmap=_mqtt_scan,
        mqtt=_mqtt_evidence,
        http=_unexpected_http,
        tls=_tls_unavailable,
    )
    detail = run_assessment(
        db_session,
        phase1_settings,
        TARGET,
        probes=probes,
    )

    assert detail.status == "COMPLETE"
    assert detail.evidence_count >= 4
    assert {finding.finding_id for finding in detail.findings} >= {
        "NET-01",
        "IOT-MQTT-01",
        "IOT-MQTT-02",
    }
    assert all(finding.evidence_reference for finding in detail.findings)
    assert detail.highest_risk == 66.5
    assert detail.highest_risk_level == "HIGH"
    assert detail.risk_snapshots
    assert any(snapshot.finding_ref is None for snapshot in detail.risk_snapshots)
    assert all(
        snapshot.score_version == "IoT-RISK-v1"
        for snapshot in detail.risk_snapshots
    )

    counts = db_session.execute(
        text(
            """
            SELECT
              (SELECT COUNT(*) FROM assessment_runs WHERE id = :id),
              (SELECT COUNT(*) FROM assessment_evidence WHERE assessment_id = :id),
              (SELECT COUNT(*) FROM assessment_findings WHERE assessment_id = :id),
              (SELECT COUNT(*) FROM risk_snapshots WHERE assessment_id = :id)
            """
        ),
        {"id": detail.id},
    ).one()
    assert counts[0] == 1
    assert counts[1] == detail.evidence_count
    assert counts[2] == detail.finding_count
    assert counts[3] == len(detail.risk_snapshots)


def test_unreachable_target_is_incomplete_and_has_no_findings(
    db_session,
    phase1_settings,
) -> None:
    probes = AssessmentProbes(
        nmap=_no_response_scan,
        mqtt=_mqtt_evidence,
        http=_unexpected_http,
        tls=_tls_unavailable,
    )
    detail = run_assessment(
        db_session,
        phase1_settings,
        TARGET,
        probes=probes,
    )
    assert detail.status == "INCOMPLETE"
    assert detail.findings == []
    assert detail.risk_snapshots == []
    assert "could not be verified" in (detail.error_summary or "")
    assert {item.result for item in detail.evidence} == {"NO_RESPONSE"}


def test_configuration_flags_alone_never_create_findings(
    db_session,
    phase1_settings,
) -> None:
    # Settings still default to MQTT_TLS_ENABLED=false and
    # MQTT_ANONYMOUS_ALLOWED=true. A closed observed listener must produce no
    # finding and must not invoke an MQTT probe.
    probes = AssessmentProbes(
        nmap=_closed_port_scan,
        mqtt=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("MQTT probe must not run for a closed listener")
        ),
        http=_unexpected_http,
        tls=_tls_unavailable,
    )
    detail = run_assessment(
        db_session,
        phase1_settings,
        TARGET,
        probes=probes,
    )
    assert phase1_settings.mqtt_tls_enabled is False
    assert phase1_settings.mqtt_anonymous_allowed is True
    assert detail.status == "COMPLETE"
    assert detail.findings == []
    assert detail.risk_snapshots == []
