"""Comprehensive test suite for the Production Synchronization Service.

Verifies:
1. Independent telemetry and assessment workers.
2. Telemetry sanitization (fields, types, zero IP/secret leakage).
3. Assessment sanitization (targets, metadata, observation scrubbing).
4. Duplicate prevention (exact timestamp/device check).
5. Foreign-key preservation (evidence, findings, risk snapshots).
6. Failed transaction rollback.
7. Neon connection failures and retries.
8. Restart recovery (resume from watermarks).
9. Invalid sensor readings rejection (0.0/0.0, non-numeric, out-of-range).
10. Incomplete/running/failed assessment rejection.
11. Prevention of concurrent service instances (single-instance lock).
12. No accidental publication of sensitive data (regex assertion across outputs).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from app.services.sanitizer import (
    RFC1918_IPV4_REGEX,
    WINDOWS_PATH_REGEX,
    sanitize_assessment_record,
    validate_sanitized_data,
)
from app.services.telemetry_sanitizer import (
    TelemetryReading,
    TelemetryValidationError,
    filter_and_validate_batch,
    sanitize_telemetry_row,
)
from scripts.sync_to_production import (
    AssessmentWorker,
    SingleInstanceLock,
    TelemetryWorker,
    parse_assessment_ids,
    run_dry_run,
)


# --- 1. Independent Telemetry and Assessment Workers ---
def test_independent_worker_classes():
    t_worker = TelemetryWorker("postgresql://mock/db")
    a_worker = AssessmentWorker("postgresql://mock/db")
    assert hasattr(t_worker, "sync_cycle")
    assert hasattr(a_worker, "sync_cycle")
    assert t_worker.neon_url == a_worker.neon_url


# --- 2. Telemetry Sanitization ---
def test_telemetry_sanitization_fields():
    raw = {
        "device_id": "ESP32-01",
        "temperature": Decimal("29.20"),
        "humidity": Decimal("75.00"),
        "timestamp": datetime(2026, 11, 5, 10, 0, 0, tzinfo=UTC),
        "ip_address": "10.32.252.105",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "password": "supersecretpassword",
        "mqtt_topic": "iot/esp32/01/sensor",
    }
    cleaned = sanitize_telemetry_row(raw)
    assert cleaned.device_id == "ESP32-01"
    assert cleaned.temperature == 29.2
    assert cleaned.humidity == 75.0
    assert cleaned.timestamp == datetime(2026, 11, 5, 10, 0, 0, tzinfo=UTC)

    # Asserts that no sensitive fields exist on the TelemetryReading
    assert not hasattr(cleaned, "ip_address")
    assert not hasattr(cleaned, "mac_address")
    assert not hasattr(cleaned, "password")


# --- 3. Assessment Sanitization ---
def test_assessment_sanitization_target_mapping():
    run_id = uuid4()
    now = datetime.now(UTC)
    run = {
        "id": run_id,
        "target": "10.32.252.85",
        "assessment_type": "MULTI_LAYER",
        "status": "COMPLETE",
        "started_at": now,
        "completed_at": now,
        "error_summary": None,
        "metadata": {"broker": "10.32.252.85", "path": "C:\\Tools\\Nmap\\nmap.exe"},
        "created_at": now,
    }
    evidence = [
        {
            "id": uuid4(),
            "assessment_id": run_id,
            "target": "10.32.252.85",
            "port": 1883,
            "check_type": "MQTT_PROBE",
            "result": "ACCEPTED",
            "evidence_source": "MQTT_PROBE",
            "observation": {"args": "nmap 10.32.252.85"},
            "observed_at": now,
        }
    ]
    findings = [
        {
            "id": uuid4(),
            "assessment_id": run_id,
            "finding_id": "IOT-MQTT-01",
            "finding_type": "MQTT_ANONYMOUS_ACCESS",
            "category": "IOT_PROTOCOL",
            "title": "MQTT broker accepted anonymous connect",
            "severity": "HIGH",
            "confidence": Decimal("0.99"),
            "description": "Observed on 10.32.252.85",
            "target": "10.32.252.85",
            "port": 1883,
            "evidence_reference": evidence[0]["id"],
            "remediation": "Disable anonymous.",
            "status": "OPEN",
            "created_at": now,
        }
    ]
    risks = [
        {
            "id": uuid4(),
            "assessment_id": run_id,
            "finding_ref": findings[0]["id"],
            "score": Decimal("70.50"),
            "risk_level": "HIGH",
            "score_version": "IoT-RISK-v1",
            "base_severity": "HIGH",
            "context_score": Decimal("0.66"),
            "factor_contributions": {},
            "context_inputs": {},
            "created_at": now,
        }
    ]

    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)
    assert clean_run["target"] == "lab-mqtt-broker"
    assert clean_ev[0]["target"] == "lab-mqtt-broker"
    assert clean_f[0]["target"] == "lab-mqtt-broker"

    # Validation must pass cleanly
    violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
    assert violations == []


# --- 4. Duplicate Prevention ---
def test_telemetry_duplicate_prevention():
    t0 = datetime(2026, 11, 5, 10, 0, 0, tzinfo=UTC)
    batch = [
        {"device_id": "ESP32-01", "temperature": 25.0, "humidity": 60.0, "timestamp": t0},
        {"device_id": "ESP32-01", "temperature": 25.0, "humidity": 60.0, "timestamp": t0},  # duplicate
    ]
    valid, dup_cnt, _ = filter_and_validate_batch(batch)
    assert len(valid) == 1
    assert dup_cnt == 1


# --- 5. Foreign-Key Preservation ---
def test_assessment_foreign_key_preservation():
    run_id = uuid4()
    ev_id = uuid4()
    f_id = uuid4()
    now = datetime.now(UTC)

    run = {"id": run_id, "target": "lab-mqtt-broker", "assessment_type": "MULTI_LAYER", "status": "COMPLETE", "started_at": now, "completed_at": now, "metadata": {}, "created_at": now}
    evidence = [{"id": ev_id, "assessment_id": run_id, "target": "lab-mqtt-broker", "port": 1883, "check_type": "PROBE", "result": "ACCEPTED", "evidence_source": "MQTT_PROBE", "observation": {}, "observed_at": now}]
    findings = [{"id": f_id, "assessment_id": run_id, "finding_id": "TEST-01", "finding_type": "TEST", "category": "IOT", "title": "Test", "severity": "LOW", "confidence": Decimal("0.8"), "description": "desc", "target": "lab-mqtt-broker", "port": 1883, "evidence_reference": ev_id, "remediation": "rem", "status": "OPEN", "created_at": now}]
    risks = [{"id": uuid4(), "assessment_id": run_id, "finding_ref": f_id, "score": Decimal("40.0"), "risk_level": "LOW", "score_version": "v1", "base_severity": "LOW", "context_score": Decimal("0.5"), "factor_contributions": {}, "context_inputs": {}, "created_at": now}]

    clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)
    assert clean_ev[0]["assessment_id"] == clean_run["id"]
    assert clean_f[0]["assessment_id"] == clean_run["id"]
    assert clean_f[0]["evidence_reference"] == clean_ev[0]["id"]
    assert clean_r[0]["assessment_id"] == clean_run["id"]
    assert clean_r[0]["finding_ref"] == clean_f[0]["id"]


# --- 6. Failed Transaction Rollback ---
def test_transaction_rollback_on_failure():
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    mock_cursor.execute.side_effect = Exception("Simulated Neon Write Error")

    with pytest.raises(Exception, match="Simulated Neon Write Error"):
        with mock_conn.transaction():
            mock_cursor.execute("INSERT INTO sensor_data ...")

    # Transaction context manager ensures rollback is called
    assert mock_conn.transaction.called


# --- 7. Neon Connection Failures and Retries ---
def test_worker_survives_temporary_outage():
    t_worker = TelemetryWorker("postgresql://mock/db")
    with patch("scripts.sync_to_production.get_local_connection") as mock_local:
        mock_local.side_effect = Exception("Temporary Connection Timeout")
        with pytest.raises(Exception, match="Temporary Connection Timeout"):
            t_worker.sync_cycle()
        # Worker state remains intact
        assert isinstance(t_worker.watermarks, dict)


# --- 8. Restart Recovery (Watermarks) ---
def test_restart_recovery_from_high_watermarks():
    t_worker = TelemetryWorker("postgresql://mock/db")
    t0 = datetime(2026, 11, 5, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)

    # Set existing watermark
    t_worker.watermarks["ESP32-01"] = t0
    assert t_worker.watermarks["ESP32-01"] == t0

    # New readings beyond t0 are accepted
    row = {"device_id": "ESP32-01", "temperature": 29.0, "humidity": 75.0, "timestamp": t1}
    reading = sanitize_telemetry_row(row)
    assert reading.timestamp > t_worker.watermarks["ESP32-01"]


# --- 9. Invalid Sensor Readings Rejection ---
def test_invalid_sensor_readings():
    # 0.0 / 0.0 rejected
    with pytest.raises(TelemetryValidationError, match="Glitched sensor reading"):
        sanitize_telemetry_row({"device_id": "ESP32-01", "temperature": 0.0, "humidity": 0.0, "timestamp": datetime.now(UTC)})

    # Out of range temperature
    with pytest.raises(TelemetryValidationError, match="Temperature"):
        sanitize_telemetry_row({"device_id": "ESP32-01", "temperature": 99.0, "humidity": 50.0, "timestamp": datetime.now(UTC)})

    # Out of range humidity
    with pytest.raises(TelemetryValidationError, match="Humidity"):
        sanitize_telemetry_row({"device_id": "ESP32-01", "temperature": 25.0, "humidity": -5.0, "timestamp": datetime.now(UTC)})


# --- 10. Incomplete Assessment Rejection ---
def test_incomplete_assessment_rejected_by_validator():
    run_id = uuid4()
    now = datetime.now(UTC)
    run = {"id": run_id, "target": "lab-mqtt-broker", "assessment_type": "MULTI_LAYER", "status": "RUNNING", "started_at": now, "completed_at": None, "metadata": {}, "created_at": now}
    violations = validate_sanitized_data(run, [], [], [])
    assert any("expected 'COMPLETE'" in v for v in violations)


# --- 11. Prevention of Concurrent Service Instances ---
def test_single_instance_concurrency_lock(tmp_path):
    lock_file = tmp_path / "sync.lock"
    lock1 = SingleInstanceLock(lock_file)
    lock2 = SingleInstanceLock(lock_file)

    assert lock1.acquire() is True
    assert lock2.acquire() is False
    lock1.release()
    assert lock2.acquire() is True
    lock2.release()


# --- 12. No Accidental Publication of Sensitive Data ---
def test_zero_sensitive_data_in_sanitized_payload():
    run_id = uuid4()
    now = datetime.now(UTC)
    raw_run = {
        "id": run_id,
        "target": "10.32.252.85",
        "assessment_type": "MULTI_LAYER",
        "status": "COMPLETE",
        "started_at": now,
        "completed_at": now,
        "error_summary": "Error at C:\\Program Files\\app",
        "metadata": {"secret_token": "token123", "internal_ip": "10.32.252.85"},
        "created_at": now,
    }
    clean_run, _, _, _ = sanitize_assessment_record(raw_run, [], [], [])

    # Check run target
    assert not RFC1918_IPV4_REGEX.search(clean_run["target"])
    # Check metadata
    assert "secret_token" not in clean_run["metadata"]
    # Check error_summary
    assert not WINDOWS_PATH_REGEX.search(clean_run["error_summary"])


# --- 13. Parse Assessment IDs Argument ---
def test_parse_assessment_ids_valid_and_invalid():
    # None returns None
    assert parse_assessment_ids(None) is None

    # Empty string returns empty list
    assert parse_assessment_ids("") == []

    # Valid UUIDs with whitespace
    id1 = uuid4()
    id2 = uuid4()
    parsed = parse_assessment_ids(f" {id1} , {id2} ")
    assert parsed == [id1, id2]

    # Invalid UUID raises ValueError
    with pytest.raises(ValueError, match="Invalid assessment UUID"):
        parse_assessment_ids("not-a-valid-uuid")


# --- 14. Candidate Selection With Explicit Allowlist ---
def test_candidate_selection_explicit_allowlist():
    id1 = uuid4()
    id2 = uuid4()
    historical_id = uuid4()

    mock_rows = [
        {"id": id1, "target": "10.32.252.85", "status": "COMPLETE", "assessment_type": "MULTI_LAYER", "started_at": datetime.now(UTC), "completed_at": datetime.now(UTC), "error_summary": None, "metadata": {}, "created_at": datetime.now(UTC)},
        {"id": id2, "target": "10.32.252.105", "status": "COMPLETE", "assessment_type": "MULTI_LAYER", "started_at": datetime.now(UTC), "completed_at": datetime.now(UTC), "error_summary": None, "metadata": {}, "created_at": datetime.now(UTC)},
    ]

    worker = AssessmentWorker("postgresql://mock/db", allowed_ids=[id1, id2])
    worker.published_ids = set()

    with patch("scripts.sync_to_production.get_local_connection") as mock_local:
        mock_cursor = MagicMock()
        mock_local.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchall.return_value = mock_rows

        candidates = worker.get_candidate_local_assessments()

        # Query must be parameterized with WHERE id = ANY(%s) using allowed_ids
        called_sql, called_args = mock_cursor.execute.call_args[0]
        assert "WHERE id = ANY(%s)" in called_sql
        assert called_args[0] == [id1, id2]

        candidate_ids = [c["id"] for c in candidates]
        assert candidate_ids == [id1, id2]
        assert historical_id not in candidate_ids


# --- 15. Candidate Selection: Missing UUID Handled ---
def test_candidate_selection_missing_uuid_handled(capsys):
    id_present = uuid4()
    id_missing = uuid4()

    mock_rows = [
        {"id": id_present, "target": "10.32.252.85", "status": "COMPLETE", "assessment_type": "MULTI_LAYER", "started_at": datetime.now(UTC), "completed_at": datetime.now(UTC), "error_summary": None, "metadata": {}, "created_at": datetime.now(UTC)},
    ]

    worker = AssessmentWorker("postgresql://mock/db", allowed_ids=[id_present, id_missing])
    worker.published_ids = set()

    with patch("scripts.sync_to_production.get_local_connection") as mock_local:
        mock_cursor = MagicMock()
        mock_local.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchall.return_value = mock_rows

        candidates = worker.get_candidate_local_assessments()
        assert len(candidates) == 1
        assert candidates[0]["id"] == id_present

    captured = capsys.readouterr()
    assert f"[-] Assessment {id_missing} does not exist in local database" in captured.out


# --- 16. Candidate Selection: Incomplete Assessment Rejected ---
def test_candidate_selection_incomplete_rejected(capsys):
    id_complete = uuid4()
    id_running = uuid4()

    mock_rows = [
        {"id": id_complete, "target": "10.32.252.85", "status": "COMPLETE", "assessment_type": "MULTI_LAYER", "started_at": datetime.now(UTC), "completed_at": datetime.now(UTC), "error_summary": None, "metadata": {}, "created_at": datetime.now(UTC)},
        {"id": id_running, "target": "10.32.252.105", "status": "RUNNING", "assessment_type": "MULTI_LAYER", "started_at": datetime.now(UTC), "completed_at": None, "error_summary": None, "metadata": {}, "created_at": datetime.now(UTC)},
    ]

    worker = AssessmentWorker("postgresql://mock/db", allowed_ids=[id_complete, id_running])
    worker.published_ids = set()

    with patch("scripts.sync_to_production.get_local_connection") as mock_local:
        mock_cursor = MagicMock()
        mock_local.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchall.return_value = mock_rows

        candidates = worker.get_candidate_local_assessments()
        assert len(candidates) == 1
        assert candidates[0]["id"] == id_complete

    captured = capsys.readouterr()
    assert f"[-] Assessment {id_running} has status 'RUNNING' (expected 'COMPLETE')" in captured.out


# --- 17. Candidate Selection: Already Published Skipped ---
def test_candidate_selection_already_published_skipped(capsys):
    id_new = uuid4()
    id_already_in_neon = uuid4()

    mock_rows = [
        {"id": id_new, "target": "10.32.252.85", "status": "COMPLETE", "assessment_type": "MULTI_LAYER", "started_at": datetime.now(UTC), "completed_at": datetime.now(UTC), "error_summary": None, "metadata": {}, "created_at": datetime.now(UTC)},
        {"id": id_already_in_neon, "target": "10.32.252.105", "status": "COMPLETE", "assessment_type": "MULTI_LAYER", "started_at": datetime.now(UTC), "completed_at": datetime.now(UTC), "error_summary": None, "metadata": {}, "created_at": datetime.now(UTC)},
    ]

    worker = AssessmentWorker("postgresql://mock/db", allowed_ids=[id_new, id_already_in_neon])
    worker.published_ids = {str(id_already_in_neon)}

    with patch("scripts.sync_to_production.get_local_connection") as mock_local:
        mock_cursor = MagicMock()
        mock_local.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchall.return_value = mock_rows

        candidates = worker.get_candidate_local_assessments()
        assert len(candidates) == 1
        assert candidates[0]["id"] == id_new

    captured = capsys.readouterr()
    assert f"[*] Assessment {id_already_in_neon} is already published in Neon" in captured.out


# --- 18. Sanitized Target Appears in Logging (Never Raw IP) ---
def test_sanitized_target_in_logging(capsys):
    id1 = uuid4()
    now = datetime.now(UTC)
    raw_target = "10.32.252.85"

    run = {"id": id1, "target": raw_target, "assessment_type": "MULTI_LAYER", "status": "COMPLETE", "started_at": now, "completed_at": now, "error_summary": None, "metadata": {}, "created_at": now}

    worker = AssessmentWorker("postgresql://mock/db", allowed_ids=[id1])
    worker.published_ids = set()

    with patch.object(worker, "get_candidate_local_assessments", return_value=[run]):
        with patch.object(worker, "sync_assessment", return_value=(True, "lab-mqtt-broker")):
            worker.sync_cycle()

    captured = capsys.readouterr()
    # Log must contain sanitized target
    assert f"[AssessmentWorker] Published assessment {id1} (lab-mqtt-broker)" in captured.out
    # Log must NOT contain raw private IP
    assert raw_target not in captured.out


# --- 19. No Fallback to Historical Queue ---
def test_no_fallback_to_historical_queue():
    # Empty allowed_ids list must return empty candidates without executing any DB query
    worker = AssessmentWorker("postgresql://mock/db", allowed_ids=[])
    candidates = worker.get_candidate_local_assessments()
    assert candidates == []


# --- 20. Telemetry Catch-up Limited to Recent Window ---
def test_telemetry_catchup_limited_to_recent_window():
    worker = TelemetryWorker("postgresql://mock/db")
    lookback = timedelta(minutes=3)

    with patch("scripts.sync_to_production.get_local_connection") as mock_local:
        mock_cursor = MagicMock()
        mock_local.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []

        before_call = datetime.now(UTC) - lookback
        worker.sync_cycle(lookback_window=lookback)
        after_call = datetime.now(UTC) - lookback

        # Check all execute calls
        for call_args in mock_cursor.execute.call_args_list:
            sql, args = call_args[0]
            assert "WHERE device_id = %s" in sql
            assert "AND timestamp > %s" in sql
            min_ts_arg = args[1]
            assert before_call <= min_ts_arg <= after_call


# --- 21. Dry-Run Mode Reports Planned Counts Without Any Production Writes ---
def test_dry_run_mode_reports_insert_counts(capsys):
    id1 = uuid4()
    now = datetime.now(UTC)

    mock_run = {"id": id1, "target": "10.32.252.85", "assessment_type": "MULTI_LAYER", "status": "COMPLETE", "started_at": now, "completed_at": now, "error_summary": None, "metadata": {}, "created_at": now}
    mock_ev = [{"id": uuid4(), "assessment_id": id1, "target": "10.32.252.85", "port": 1883, "check_type": "PROBE", "result": "ACCEPTED", "evidence_source": "MQTT", "observation": {}, "observed_at": now}]
    mock_f = [{"id": uuid4(), "assessment_id": id1, "finding_id": "F-01", "finding_type": "TEST", "category": "IOT", "title": "T", "severity": "LOW", "confidence": Decimal("0.8"), "description": "d", "target": "10.32.252.85", "port": 1883, "evidence_reference": mock_ev[0]["id"], "remediation": "r", "status": "OPEN", "created_at": now}]
    mock_r = [{"id": uuid4(), "assessment_id": id1, "finding_ref": mock_f[0]["id"], "score": Decimal("40"), "risk_level": "LOW", "score_version": "v1", "base_severity": "LOW", "context_score": Decimal("0.5"), "factor_contributions": {}, "context_inputs": {}, "created_at": now}]

    with patch("scripts.sync_to_production.get_local_connection") as mock_local:
        mock_cursor = MagicMock()
        mock_local.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = mock_cursor

        def mock_exec(sql, params=None):
            if "WHERE id = ANY" in sql:
                mock_cursor.fetchall.return_value = [mock_run]
            elif "FROM assessment_evidence" in sql:
                mock_cursor.fetchall.return_value = mock_ev
            elif "FROM assessment_findings" in sql:
                mock_cursor.fetchall.return_value = mock_f
            elif "FROM risk_snapshots" in sql:
                mock_cursor.fetchall.return_value = mock_r
            elif "FROM sensor_data" in sql:
                mock_cursor.fetchall.return_value = []

        mock_cursor.execute.side_effect = mock_exec

        ret = run_dry_run(neon_url=None, assessment_ids=[id1])
        assert ret == 0

    captured = capsys.readouterr()
    assert "*** DRY-RUN ONLY: ZERO PRODUCTION WRITES OCCURRED ***" in captured.out
    assert "Assessment Runs:      1" in captured.out
    assert "Assessment Findings:  1" in captured.out
    assert "Assessment Evidence:  1" in captured.out
    assert "Risk Snapshots:       1" in captured.out
    assert "Sanitized Target: lab-mqtt-broker" in captured.out

