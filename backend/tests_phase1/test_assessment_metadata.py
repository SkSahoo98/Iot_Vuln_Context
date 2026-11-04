"""Phase 3F-A: configuration metadata and execution-based check coverage."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from app.schemas.assessment import AssessmentDetailOut, AssessmentSummaryOut
from app.services.assessment_service import (
    AssessmentProbes,
    get_assessment,
    run_assessment,
)
from scanner.core.catalog import CHECK_CATALOG_VERSION, CHECKS
from scanner.core.coverage import (
    EVALUATED,
    NOT_APPLICABLE,
    NOT_EVALUATED,
    CheckCoverage,
    http_coverage,
    mqtt_coverage,
    tls_coverage,
)
from scanner.core.models import Evidence
from scanner.network_checks.nmap_scanner import (
    NmapError,
    NmapScanResult,
    PortObservation,
)
from scanner.targets import TargetNotAllowedError

TARGET = "10.84.237.85"
EXPECTED_PORTS = [21, 22, 23, 80, 443, 1883, 8080, 8443, 8883]
LEGACY_METADATA = {
    "ports": EXPECTED_PORTS,
    "nmap_arguments": ["-sT", "-Pn", "-sV"],
    "nmap_timeout_seconds": 5,
    "probe_timeout_seconds": 0.1,
    "open_service_threshold": 5,
}


def _scan(*open_ports: PortObservation):
    def scan(target, ports, *, nmap_path, timeout_seconds) -> NmapScanResult:
        return NmapScanResult(
            target=target,
            host_state="up",
            nmap_version="test",
            args="mocked",
            ports=list(open_ports),
        )

    return scan


def _open(port: int, service: str) -> PortObservation:
    return PortObservation(
        port=port, protocol="tcp", state="open", reason="syn-ack", service_name=service
    )


def _mqtt(result: str, **observation):
    def probe(target, port, timeout) -> Evidence:
        return Evidence(
            target=target,
            port=port,
            check_type="MQTT_ANONYMOUS_CONNECT",
            result=result,
            evidence_source="MQTT_PROBE",
            observation={"reason_code": 0, "broker_version": None, **observation},
        )

    return probe


def _tls(result: str, **observation):
    def probe(target, port, timeout) -> Evidence:
        return Evidence(
            target=target,
            port=port,
            check_type="TLS_HANDSHAKE",
            result=result,
            evidence_source="TLS_PROBE",
            observation=observation,
        )

    return probe


def _not_called(*args, **kwargs):
    raise AssertionError("Probe must not run in this scenario")


def _coverage(detail) -> dict[tuple[str, int | None], str]:
    entries = detail.metadata["checks_evaluated"]
    return {(item["check_id"], item["port"]): item["status"] for item in entries}


def _assert_full_catalog(detail) -> None:
    assert {item["check_id"] for item in detail.metadata["checks_evaluated"]} == set(
        CHECKS
    )


def _assert_all_not_evaluated(detail) -> None:
    _assert_full_catalog(detail)
    assert all(
        item["status"] == NOT_EVALUATED and item["port"] is None
        for item in detail.metadata["checks_evaluated"]
    )


def test_metadata_records_configuration_and_preserves_existing_keys(
    db_session,
    phase1_settings,
) -> None:
    probes = AssessmentProbes(
        nmap=_scan(_open(1883, "mqtt")),
        mqtt=_mqtt("ACCEPTED", connection_accepted=True),
        http=_not_called,
        tls=_tls("REFUSED", error_type="ConnectionRefusedError"),
    )
    detail = run_assessment(db_session, phase1_settings, TARGET, probes=probes)

    for key, value in LEGACY_METADATA.items():
        assert detail.metadata[key] == value
    assert detail.metadata["mqtt_broker_port"] == phase1_settings.mqtt_broker_port
    assert detail.metadata["mqtt_tls_port"] == phase1_settings.mqtt_tls_port
    assert detail.metadata["admin_service_ports"] == [22]
    assert detail.metadata["check_catalog_version"] == CHECK_CATALOG_VERSION

    # Findings and risk are identical to the pre-3F-A behaviour.
    assert detail.status == "COMPLETE"
    assert sorted(f.finding_id for f in detail.findings) == [
        "IOT-MQTT-01",
        "IOT-MQTT-02",
        "NET-01",
    ]
    assert detail.highest_risk == 66.5
    assert detail.highest_risk_level == "HIGH"
    assert {s.score_version for s in detail.risk_snapshots} == {"IoT-RISK-v1"}

    _assert_full_catalog(detail)
    coverage = _coverage(detail)
    for check_id in ("NET-01", "NET-02", "NET-03", "NET-04", "NET-06"):
        assert coverage[(check_id, None)] == EVALUATED
    assert coverage[("IOT-MQTT-01", 1883)] == EVALUATED
    assert coverage[("IOT-MQTT-02", 1883)] == EVALUATED
    # The probe did not report a $SYS subscription, so IOT-MQTT-03 is unknown.
    assert coverage[("IOT-MQTT-03", 1883)] == NOT_EVALUATED
    for check_id in ("WEB-01", "WEB-02", "WEB-03"):
        assert coverage[(check_id, None)] == NOT_APPLICABLE
    for check_id in ("TLS-01", "TLS-02", "TLS-03", "TLS-04"):
        assert coverage[(check_id, None)] == NOT_APPLICABLE


def test_coverage_is_derived_from_execution_not_findings(
    db_session,
    phase1_settings,
) -> None:
    probes = AssessmentProbes(
        nmap=_scan(_open(1883, "mqtt"), _open(8883, "secure-mqtt")),
        mqtt=_mqtt("ACCEPTED", connection_accepted=True, sys_topic_checked=True),
        http=_not_called,
        tls=_tls(
            "AVAILABLE",
            tls_version="TLSv1.3",
            certificate_not_after="Jun  1 12:00:00 2099 GMT",
            certificate_verified=False,
        ),
    )
    detail = run_assessment(db_session, phase1_settings, TARGET, probes=probes)
    finding_ids = {f.finding_id for f in detail.findings}
    coverage = _coverage(detail)

    # Evaluated checks that produced no finding.
    assert not finding_ids & {"IOT-MQTT-02", "IOT-MQTT-03", "TLS-02", "TLS-03"}
    assert coverage[("IOT-MQTT-02", 1883)] == EVALUATED
    assert coverage[("IOT-MQTT-03", 1883)] == EVALUATED
    assert coverage[("TLS-02", 8883)] == EVALUATED
    assert coverage[("TLS-03", 8883)] == EVALUATED
    # Evaluated checks that produced a finding.
    assert {"TLS-01", "TLS-04"} <= finding_ids
    assert coverage[("TLS-01", 8883)] == EVALUATED
    assert coverage[("TLS-04", 8883)] == EVALUATED


def test_failed_probes_are_never_marked_evaluated(
    db_session,
    phase1_settings,
) -> None:
    def http_probe(target, port, scheme, timeout) -> Evidence:
        if port == 8080:
            return Evidence(
                target=target,
                port=port,
                check_type="HTTP_RESPONSE",
                result="AVAILABLE",
                evidence_source="HTTP_PROBE",
                observation={"scheme": scheme, "status_code": 200, "headers": {}},
            )
        return Evidence(
            target=target,
            port=port,
            check_type="HTTP_RESPONSE",
            result="TIMEOUT",
            evidence_source="HTTP_PROBE",
            observation={"scheme": scheme, "error_type": "ReadTimeout"},
        )

    probes = AssessmentProbes(
        nmap=_scan(_open(80, "http"), _open(443, "https"), _open(8080, "http-proxy")),
        mqtt=_not_called,
        http=http_probe,
        tls=_tls("TIMEOUT", error_type="TimeoutError"),
    )
    detail = run_assessment(db_session, phase1_settings, TARGET, probes=probes)
    coverage = _coverage(detail)

    assert detail.status == "INCOMPLETE"
    for check_id in ("WEB-01", "WEB-02", "WEB-03"):
        assert coverage[(check_id, 80)] == NOT_EVALUATED
        assert coverage[(check_id, 443)] == NOT_EVALUATED
        assert coverage[(check_id, 8080)] == EVALUATED
    for check_id in ("TLS-01", "TLS-02", "TLS-03", "TLS-04"):
        assert coverage[(check_id, 443)] == NOT_EVALUATED
    for check_id in ("IOT-MQTT-01", "IOT-MQTT-02", "IOT-MQTT-03"):
        assert coverage[(check_id, 1883)] == NOT_APPLICABLE


def test_unresponsive_target_records_nothing_as_evaluated(
    db_session,
    phase1_settings,
) -> None:
    def no_response(target, ports, *, nmap_path, timeout_seconds) -> NmapScanResult:
        return NmapScanResult(
            target=target,
            host_state="up",
            nmap_version="test",
            args="mocked",
            ports=[],
            extraports={"filtered": len(ports)},
        )

    probes = AssessmentProbes(
        nmap=no_response, mqtt=_not_called, http=_not_called, tls=_not_called
    )
    detail = run_assessment(db_session, phase1_settings, TARGET, probes=probes)

    assert detail.status == "INCOMPLETE"
    assert detail.findings == []
    assert detail.metadata["check_catalog_version"] == CHECK_CATALOG_VERSION
    # Admin ports were never consumed by the network rules in this run.
    assert "admin_service_ports" not in detail.metadata
    _assert_all_not_evaluated(detail)


def test_nmap_error_records_nothing_as_evaluated(
    db_session,
    phase1_settings,
) -> None:
    def failing_nmap(*args, **kwargs):
        raise NmapError("Nmap executable not found: mocked")

    probes = AssessmentProbes(
        nmap=failing_nmap, mqtt=_not_called, http=_not_called, tls=_not_called
    )
    detail = run_assessment(db_session, phase1_settings, TARGET, probes=probes)

    assert detail.status == "INCOMPLETE"
    _assert_all_not_evaluated(detail)


def test_execution_error_discards_partial_coverage(
    db_session,
    phase1_settings,
) -> None:
    def crashing_mqtt(*args, **kwargs):
        raise RuntimeError("mocked probe crash")

    probes = AssessmentProbes(
        nmap=_scan(_open(1883, "mqtt")),
        mqtt=crashing_mqtt,
        http=_not_called,
        tls=_not_called,
    )
    detail = run_assessment(db_session, phase1_settings, TARGET, probes=probes)

    assert detail.status == "FAILED"
    for key, value in LEGACY_METADATA.items():
        assert detail.metadata[key] == value
    # NET-* had been evaluated in memory, but the run failed before persisting.
    _assert_all_not_evaluated(detail)


def test_allowlist_rejection_is_unchanged(db_session, phase1_settings) -> None:
    before = db_session.execute(text("SELECT COUNT(*) FROM assessment_runs")).scalar_one()
    probes = AssessmentProbes(
        nmap=_not_called, mqtt=_not_called, http=_not_called, tls=_not_called
    )
    with pytest.raises(TargetNotAllowedError):
        run_assessment(db_session, phase1_settings, "8.8.8.8", probes=probes)
    after = db_session.execute(text("SELECT COUNT(*) FROM assessment_runs")).scalar_one()
    assert after == before


def test_legacy_metadata_without_new_fields_still_parses(db_session) -> None:
    run_id = db_session.execute(
        text(
            """
            INSERT INTO assessment_runs (target, status, assessment_type, metadata)
            VALUES (:target, 'COMPLETE', 'MULTI_LAYER', CAST(:metadata AS jsonb))
            RETURNING id
            """
        ),
        {"target": TARGET, "metadata": json.dumps(LEGACY_METADATA)},
    ).scalar_one()

    detail = get_assessment(db_session, run_id)
    assert detail is not None
    assert detail.metadata == LEGACY_METADATA

    now = datetime.now(UTC)
    summary = AssessmentSummaryOut.model_validate(
        {
            "id": run_id,
            "target": TARGET,
            "assessment_type": "MULTI_LAYER",
            "status": "COMPLETE",
            "started_at": now,
            "completed_at": now,
            "error_summary": None,
            "metadata": LEGACY_METADATA,
            "created_at": now,
        }
    )
    assert summary.metadata == LEGACY_METADATA


def test_response_structure_is_unchanged() -> None:
    assert set(AssessmentDetailOut.model_fields) == {
        "id",
        "target",
        "assessment_type",
        "status",
        "started_at",
        "completed_at",
        "error_summary",
        "metadata",
        "created_at",
        "evidence_count",
        "finding_count",
        "highest_risk",
        "highest_risk_level",
        "evidence",
        "findings",
        "risk_snapshots",
        "risk_trace",
    }


def _evidence(result: str, **observation) -> Evidence:
    return Evidence(
        target=TARGET,
        port=1,
        check_type="TEST",
        result=result,
        evidence_source="ACTIVE_PROBE",
        observation=observation,
    )


def test_mqtt_coverage_rules() -> None:
    tls_refused = _evidence("REFUSED")
    assert mqtt_coverage(_evidence("REJECTED"), tls_refused) == {
        "IOT-MQTT-01": EVALUATED,
        "IOT-MQTT-02": NOT_APPLICABLE,
        "IOT-MQTT-03": NOT_APPLICABLE,
    }
    for result in ("TIMEOUT", "REFUSED", "UNREACHABLE", "PROTOCOL_ERROR"):
        assert set(mqtt_coverage(_evidence(result), tls_refused).values()) == {
            NOT_EVALUATED
        }
    accepted = _evidence("ACCEPTED", sys_topic_checked=False)
    assert mqtt_coverage(accepted, _evidence("ERROR"))["IOT-MQTT-02"] == NOT_EVALUATED
    assert mqtt_coverage(accepted, tls_refused)["IOT-MQTT-03"] == NOT_EVALUATED


def test_http_and_tls_coverage_rules() -> None:
    https = http_coverage(_evidence("AVAILABLE", scheme="https", headers={}))
    assert https == {
        "WEB-01": NOT_APPLICABLE,
        "WEB-02": EVALUATED,
        "WEB-03": EVALUATED,
    }
    assert set(http_coverage(_evidence("UNAVAILABLE", scheme="http")).values()) == {
        NOT_EVALUATED
    }

    incomplete_tls = tls_coverage(
        _evidence("AVAILABLE", certificate_not_after="not a date")
    )
    assert incomplete_tls == {
        "TLS-01": EVALUATED,
        "TLS-02": NOT_EVALUATED,
        "TLS-03": NOT_EVALUATED,
        "TLS-04": NOT_EVALUATED,
    }
    assert set(tls_coverage(_evidence("REFUSED")).values()) == {NOT_EVALUATED}


def test_coverage_merge_is_conservative_and_deterministic() -> None:
    coverage = CheckCoverage()
    coverage.record({"WEB-02": EVALUATED}, 80)
    coverage.record({"WEB-02": NOT_EVALUATED}, 80)
    coverage.record({"WEB-02": EVALUATED}, 8080)
    entries = coverage.to_metadata()

    assert {"check_id": "WEB-02", "port": 80, "status": NOT_EVALUATED} in entries
    assert {"check_id": "WEB-02", "port": 8080, "status": EVALUATED} in entries
    assert entries == sorted(
        entries,
        key=lambda item: (item["check_id"], -1 if item["port"] is None else item["port"]),
    )
    assert entries == coverage.to_metadata()
    with pytest.raises(ValueError):
        coverage.record({"NOT-A-CHECK": EVALUATED}, None)
    with pytest.raises(ValueError):
        coverage.record({"WEB-01": "RESOLVED"}, None)
