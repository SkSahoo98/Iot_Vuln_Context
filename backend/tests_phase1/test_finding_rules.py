from __future__ import annotations

from app.services.finding_service import list_findings
from scanner.core.findings import make_finding
from scanner.core.models import Evidence
from scanner.http_checks.http_probe import evaluate_http
from scanner.mqtt_checks.mqtt_rules import evaluate_mqtt
from scanner.tls_checks.tls_probe import evaluate_tls

TARGET = "10.84.237.85"


def _evidence(
    check_type: str,
    result: str,
    source: str,
    *,
    port: int,
    observation: dict | None = None,
) -> Evidence:
    return Evidence(
        target=TARGET,
        port=port,
        check_type=check_type,
        result=result,
        evidence_source=source,
        observation=observation or {},
    )


def test_mqtt_findings_require_observed_accepted_connection() -> None:
    rejected = _evidence(
        "MQTT_ANONYMOUS_CONNECT",
        "REJECTED",
        "MQTT_PROBE",
        port=1883,
        observation={"reason_code": 5},
    )
    no_tls = _evidence(
        "TLS_HANDSHAKE",
        "REFUSED",
        "TLS_PROBE",
        port=8883,
    )
    assert evaluate_mqtt(rejected, no_tls) == []


def test_observed_mqtt_results_create_traceable_findings() -> None:
    accepted = _evidence(
        "MQTT_ANONYMOUS_CONNECT",
        "ACCEPTED",
        "MQTT_PROBE",
        port=1883,
        observation={"reason_code": 0, "broker_version": "Mosquitto observed"},
    )
    no_tls = _evidence(
        "TLS_HANDSHAKE",
        "REFUSED",
        "TLS_PROBE",
        port=8883,
    )
    findings = evaluate_mqtt(accepted, no_tls)
    assert {finding.finding_id for finding in findings} == {
        "IOT-MQTT-01",
        "IOT-MQTT-02",
        "IOT-MQTT-03",
    }
    assert all(finding.evidence.evidence_source != "CONFIGURATION" for finding in findings)


def test_configuration_cannot_be_vulnerability_evidence() -> None:
    configured = _evidence(
        "EXPECTED_MQTT_STATE",
        "INSECURE",
        "CONFIGURATION",
        port=1883,
    )
    try:
        make_finding(
            "IOT-MQTT-01",
            configured,
            description="Configured, not observed",
            confidence=0.1,
        )
    except ValueError as exc:
        assert "Configuration" in str(exc)
    else:
        raise AssertionError("Configuration evidence must not create findings")


def test_legacy_finding_service_does_not_use_configuration(
    phase1_settings,
) -> None:
    assert phase1_settings.mqtt_tls_enabled is False
    assert phase1_settings.mqtt_anonymous_allowed is True
    assert list_findings(phase1_settings) == []


def test_http_rules_are_based_on_response_headers() -> None:
    observed = _evidence(
        "HTTP_RESPONSE",
        "AVAILABLE",
        "HTTP_PROBE",
        port=80,
        observation={
            "scheme": "http",
            "status_code": 200,
            "headers": {"server": "LabServer/1.0"},
        },
    )
    findings = evaluate_http(observed, https_available=False)
    assert {finding.finding_id for finding in findings} == {
        "WEB-01",
        "WEB-02",
        "WEB-03",
    }


def test_tls_rules_do_not_report_unavailable_tls_as_invalid_certificate() -> None:
    unavailable = _evidence(
        "TLS_HANDSHAKE",
        "UNAVAILABLE",
        "TLS_PROBE",
        port=443,
    )
    assert evaluate_tls(unavailable) == []


def test_tls_rules_report_only_observed_properties() -> None:
    available = _evidence(
        "TLS_HANDSHAKE",
        "AVAILABLE",
        "TLS_PROBE",
        port=443,
        observation={
            "tls_version": "TLSv1.3",
            "certificate_verified": False,
            "verification_error": "self-signed certificate",
        },
    )
    findings = evaluate_tls(available)
    assert {finding.finding_id for finding in findings} == {"TLS-01", "TLS-04"}
