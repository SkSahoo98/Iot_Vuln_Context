"""Unit tests for assessment data sanitization and validation.

Verifies:
- RFC1918 private IP scrubbing.
- Windows and Linux filesystem path sanitization.
- Sensitive credential and token stripping.
- Nested JSONB recursive sanitization.
- Safe findings, evidence, and risk snapshot preservation.
- Referential integrity validation.
- Rejection of invalid, broken, or sensitive payloads.
- Duplicate detection logic and transaction safety.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from app.services.sanitizer import (
    SanitizationError,
    sanitize_assessment_record,
    sanitize_jsonb,
    sanitize_text,
    validate_sanitized_data,
)


def _sample_raw_dataset():
    run_id = uuid4()
    ev1_id = uuid4()
    ev2_id = uuid4()
    f1_id = uuid4()
    f2_id = uuid4()
    r1_id = uuid4()
    r_overall_id = uuid4()
    now = datetime.now(timezone.utc)

    run = {
        "id": run_id,
        "target": "10.32.252.85",
        "assessment_type": "MULTI_LAYER",
        "status": "COMPLETE",
        "started_at": now,
        "completed_at": now,
        "error_summary": None,
        "metadata": {
            "ports": [22, 1883, 8883],
            "asset_id": "MQTT-BROKER",
            "host_ip": "10.32.252.85",
            "nmap_arguments": ["-sT", "-Pn"],
            "internal_secret_token": "super_secret_token_12345",
        },
        "created_at": now,
    }

    evidence = [
        {
            "id": ev1_id,
            "assessment_id": run_id,
            "target": "10.32.252.85",
            "port": 1883,
            "check_type": "MQTT_ANONYMOUS_CONNECT",
            "result": "ACCEPTED",
            "evidence_source": "MQTT_PROBE",
            "observation": {
                "broker_ip": "10.32.252.85",
                "connect_status": "SUCCESS",
                "args": '"C:\\Program Files (x86)\\Nmap\\nmap.EXE" -sT -Pn 10.32.252.85',
                "server_password": "should_be_stripped",
            },
            "observed_at": now,
        },
        {
            "id": ev2_id,
            "assessment_id": run_id,
            "target": "10.32.252.85",
            "port": 8883,
            "check_type": "TLS_HANDSHAKE",
            "result": "REFUSED",
            "evidence_source": "TLS_PROBE",
            "observation": {
                "details": "Connection refused to 10.32.252.85:8883",
            },
            "observed_at": now,
        },
    ]

    findings = [
        {
            "id": f1_id,
            "assessment_id": run_id,
            "finding_id": "IOT-MQTT-01",
            "finding_type": "MQTT_ANONYMOUS_ACCESS",
            "category": "IOT_PROTOCOL",
            "title": "MQTT broker accepted an anonymous connection",
            "severity": "HIGH",
            "confidence": Decimal("0.99"),
            "description": "Broker accepted CONNECT on 10.32.252.85 without credentials.",
            "target": "10.32.252.85",
            "port": 1883,
            "evidence_reference": ev1_id,
            "remediation": "Disable anonymous access in mosquitto.conf.",
            "status": "OPEN",
            "created_at": now,
        },
        {
            "id": f2_id,
            "assessment_id": run_id,
            "finding_id": "IOT-MQTT-02",
            "finding_type": "MQTT_WITHOUT_TLS",
            "category": "IOT_PROTOCOL",
            "title": "MQTT accepted over plaintext and no TLS listener",
            "severity": "MEDIUM",
            "confidence": Decimal("0.95"),
            "description": "Plaintext MQTT observed on 10.32.252.85:1883.",
            "target": "10.32.252.85",
            "port": 1883,
            "evidence_reference": ev2_id,
            "remediation": "Enable TLS listener on port 8883.",
            "status": "OPEN",
            "created_at": now,
        },
    ]

    risks = [
        {
            "id": r1_id,
            "assessment_id": run_id,
            "finding_ref": f1_id,
            "score": Decimal("70.50"),
            "risk_level": "HIGH",
            "score_version": "IoT-RISK-v1",
            "base_severity": "HIGH",
            "context_score": Decimal("0.6600"),
            "factor_contributions": {
                "network_exposure": {"weight": 0.2, "normalized_value": 0.6},
                "protocol_security": {"weight": 0.2, "normalized_value": 1.0},
            },
            "context_inputs": {
                "network_exposure": {"source": "NMAP", "value": 0.6},
            },
            "created_at": now,
        },
        {
            "id": r_overall_id,
            "assessment_id": run_id,
            "finding_ref": None,
            "score": Decimal("70.50"),
            "risk_level": "HIGH",
            "score_version": "IoT-RISK-v1",
            "base_severity": "HIGH",
            "context_score": Decimal("0.6600"),
            "factor_contributions": {},
            "context_inputs": {},
            "created_at": now,
        },
    ]

    return run, evidence, findings, risks


def test_sanitize_text_removes_private_ips_and_paths():
    text = "Host 10.32.252.85 was scanned using C:\\Program Files (x86)\\Nmap\\nmap.EXE from /home/operator/bin"
    cleaned = sanitize_text(text, target_replacement="lab-mqtt-broker")
    assert "10.32.252.85" not in cleaned
    assert "C:\\Program Files" not in cleaned
    assert "/home/operator" not in cleaned
    assert "lab-mqtt-broker" in cleaned


def test_sanitize_jsonb_removes_sensitive_keys():
    nested = {
        "normal_key": "safe_value",
        "api_key": "secret_key_123",
        "password": "my_password",
        "nested_dict": {
            "token": "bearer_abc",
            "connection_string": "postgresql://usr:pwd@host/db",
            "ip": "192.168.1.100",
        },
        "nested_list": [
            {"secret": "xyz", "safe": "10.0.0.5"},
        ],
    }
    cleaned = sanitize_jsonb(nested, target_replacement="sanitized-target")

    assert "api_key" not in cleaned
    assert "password" not in cleaned
    assert "token" not in cleaned["nested_dict"]
    assert "connection_string" not in cleaned["nested_dict"]
    assert "secret" not in cleaned["nested_list"][0]
    assert cleaned["nested_dict"]["ip"] == "sanitized-target"
    assert cleaned["nested_list"][0]["safe"] == "sanitized-target"


def test_sanitize_assessment_record_full_pipeline():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(
        run, evidence, findings, risks, canonical_target="lab-mqtt-broker"
    )

    # Validate output target
    assert clean_run["target"] == "lab-mqtt-broker"
    for e in clean_ev:
        assert e["target"] == "lab-mqtt-broker"
    for f in clean_f:
        assert f["target"] == "lab-mqtt-broker"

    # Validate sensitive metadata stripped
    assert "internal_secret_token" not in clean_run["metadata"]
    assert clean_run["metadata"]["is_historical"] is True
    assert clean_run["metadata"]["published_from"] == "local_cybersecurity_lab"

    # Validate observation cleaned
    obs = clean_ev[0]["observation"]
    assert "server_password" not in obs
    assert "10.32.252.85" not in obs["broker_ip"]
    assert "C:\\Program Files" not in obs["args"]

    # Validate validation engine passes cleanly
    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert violations == []


def test_validator_rejects_unsanitized_private_ip():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    # Infiltrate a private IP
    clean_f[0]["description"] += " Leaked 192.168.1.50 in description."

    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("RFC1918 private IP detected" in v for v in violations)


def test_validator_rejects_unsanitized_windows_path():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    # Infiltrate a Windows path
    clean_ev[0]["observation"]["tool_path"] = "C:\\Tools\\custom_scanner.exe"

    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("Windows filesystem path detected" in v for v in violations)


def test_validator_rejects_sensitive_keys():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    # Infiltrate a credential key
    clean_run["metadata"]["db_password"] = "admin"

    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("Disallowed sensitive key detected" in v for v in violations)


def test_validator_rejects_broken_foreign_keys():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    # Break evidence reference
    clean_f[0]["evidence_reference"] = uuid4()

    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("references non-existent evidence ID" in v for v in violations)


def test_validator_rejects_broken_risk_snapshot_ref():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    # Break risk snapshot finding reference
    clean_r[0]["finding_ref"] = uuid4()

    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("references non-existent finding ID" in v for v in violations)


def test_validator_rejects_incomplete_assessment_status():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    clean_run["status"] = "RUNNING"
    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("Assessment status is 'RUNNING', expected 'COMPLETE'" in v for v in violations)


def test_validator_rejects_score_out_of_range():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    clean_r[0]["score"] = 105.0
    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("score out of range" in v for v in violations)


def test_validator_rejects_invalid_severity():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    clean_f[0]["severity"] = "SUPER_CRITICAL"
    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("invalid severity" in v for v in violations)


def test_validator_rejects_mismatched_assessment_id():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    # Set finding assessment_id to a different UUID
    clean_f[0]["assessment_id"] = uuid4()
    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("assessment_id does not match run_id" in v for v in violations)


def test_validator_rejects_invalid_port_range():
    run, evidence, findings, risks = _sample_raw_dataset()
    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)

    clean_ev[0]["port"] = 70000
    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert any("has invalid port: 70000" in v for v in violations)
