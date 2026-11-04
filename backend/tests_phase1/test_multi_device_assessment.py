"""Tests for dynamic multi-device IoT security assessment, asset classification, and posture aggregation."""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import UUID

import pytest
from sqlalchemy import text

from app.core.config import Settings
from app.schemas.api import DeviceOut
from app.services.assessment_service import AssessmentProbes, run_assessment
from app.services.multi_device_coordinator import (
    AssessableAsset,
    AssessableDevice,
    get_assessable_devices,
    get_authorized_iot_assets,
    run_environment_assessment,
)
from scanner.core.models import Evidence
from scanner.network_checks.nmap_scanner import NmapError, NmapScanResult, PortObservation
from scanner.targets import TargetNotAllowedError


def _mock_scan(target: str, ports: list[int], *, nmap_path: str, timeout_seconds: int) -> NmapScanResult:
    # Broker has 1883 open; ESP32 devices have closed ports
    if target == "10.32.252.85":
        return NmapScanResult(
            target=target,
            host_state="up",
            nmap_version="test",
            args="mocked",
            ports=[
                PortObservation(port=1883, protocol="tcp", state="open", reason="syn-ack", service_name="mqtt"),
            ],
        )
    return NmapScanResult(
        target=target,
        host_state="up",
        nmap_version="test",
        args="mocked",
        ports=[
            PortObservation(port=1883, protocol="tcp", state="closed", reason="conn-refused"),
        ],
    )


def _mock_mqtt(target: str, port: int, *, timeout: float) -> Evidence:
    if target == "10.32.252.85":
        return Evidence(
            target=target,
            port=port,
            check_type="MQTT_ANONYMOUS_CONNECT",
            result="ACCEPTED",
            evidence_source="MQTT_PROBE",
            observation={"reason_code": 0, "broker_version": "test-mosquitto"},
        )
    raise AssertionError(f"MQTT probe should not be called on target {target} with closed ports")


def _mock_tls(target: str, port: int, *, timeout: float) -> Evidence:
    return Evidence(
        target=target,
        port=port,
        check_type="MQTT_TLS_LISTENER",
        result="REFUSED",
        evidence_source="TLS_PROBE",
        observation={"error": "connection refused"},
    )


def _not_called(*args, **kwargs) -> Evidence:
    raise AssertionError("Probe should not be called")


@pytest.fixture
def mock_probes() -> AssessmentProbes:
    return AssessmentProbes(
        nmap=_mock_scan,
        mqtt=_mock_mqtt,
        http=_not_called,
        tls=_mock_tls,
    )


@pytest.fixture
def lab_settings(phase1_settings) -> Settings:
    return Settings(
        _env_file=None,
        DATABASE_URL=phase1_settings.database_url,
        ASSESSMENT_ALLOWED_TARGETS="10.32.252.105,10.32.252.57",
        MQTT_BROKER_HOST="10.32.252.85",
        ASSESSMENT_PORTS="1883,8883",
        ASSESSMENT_MAX_OPEN_SERVICES=5,
        ASSESSMENT_ADMIN_SERVICE_PORTS="22",
        ASSESSMENT_PROBE_TIMEOUT_SECONDS=0.1,
        NMAP_TIMEOUT_SECONDS=5,
    )


@pytest.fixture
def lab_with_broker_settings(phase1_settings) -> Settings:
    return Settings(
        _env_file=None,
        DATABASE_URL=phase1_settings.database_url,
        ASSESSMENT_ALLOWED_TARGETS="10.32.252.105,10.32.252.57,10.32.252.85",
        MQTT_BROKER_HOST="10.32.252.85",
        ASSESSMENT_PORTS="1883,8883",
        ASSESSMENT_MAX_OPEN_SERVICES=5,
        ASSESSMENT_ADMIN_SERVICE_PORTS="22",
        ASSESSMENT_PROBE_TIMEOUT_SECONDS=0.1,
        NMAP_TIMEOUT_SECONDS=5,
    )


def _seed_device(
    db_session,
    device_id: str,
    ip: str,
    device_type: str = "ESP32",
    status: str = "ONLINE",
) -> None:
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, device_type, status, updated_at)
            VALUES (:device_id, CAST(:ip AS inet), :device_type, :status, NOW())
            ON CONFLICT (device_id) DO UPDATE
            SET ip_address = CAST(:ip AS inet), device_type = :device_type, status = :status, updated_at = NOW()
            """
        ),
        {"device_id": device_id, "ip": ip, "device_type": device_type, "status": status},
    )
    # Add telemetry so list_devices marks status as ONLINE
    db_session.execute(
        text(
            """
            INSERT INTO sensor_data (device_id, temperature, humidity, timestamp)
            VALUES (:device_id, 30.0, 70.0, NOW())
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_authorized_broker_and_devices_selected_and_classified(
    db_session, lab_with_broker_settings
) -> None:
    """ESP32-01, ESP32-02, and MQTT Broker are selected and classified correctly."""
    _seed_device(db_session, "ESP32-01", "10.32.252.105", device_type="ESP32")
    _seed_device(db_session, "ESP32-02", "10.32.252.57", device_type="ESP32")

    assets = get_authorized_iot_assets(db_session, lab_with_broker_settings)
    assert len(assets) == 3

    by_id = {a.asset_id: a for a in assets}
    assert "ESP32-01" in by_id
    assert "ESP32-02" in by_id
    assert "MQTT-BROKER" in by_id

    # Verify classification
    assert by_id["ESP32-01"].asset_category == "IOT_DEVICE"
    assert by_id["ESP32-01"].asset_type == "ESP32"
    assert by_id["ESP32-01"].ip_address == "10.32.252.105"

    assert by_id["ESP32-02"].asset_category == "IOT_DEVICE"
    assert by_id["ESP32-02"].asset_type == "ESP32"
    assert by_id["ESP32-02"].ip_address == "10.32.252.57"

    assert by_id["MQTT-BROKER"].asset_category == "IOT_INFRASTRUCTURE"
    assert by_id["MQTT-BROKER"].asset_type == "MQTT_BROKER"
    assert by_id["MQTT-BROKER"].ip_address == "10.32.252.85"


def test_unauthorized_broker_is_excluded(db_session, lab_settings) -> None:
    """When broker IP (10.32.252.85) is not in ASSESSMENT_ALLOWED_TARGETS, it is strictly excluded."""
    _seed_device(db_session, "ESP32-01", "10.32.252.105")
    _seed_device(db_session, "ESP32-02", "10.32.252.57")

    assets = get_authorized_iot_assets(db_session, lab_settings)
    target_ips = {a.ip_address for a in assets}

    assert "10.32.252.105" in target_ips
    assert "10.32.252.57" in target_ips
    assert "10.32.252.85" not in target_ips
    assert not any(a.asset_id == "MQTT-BROKER" for a in assets)


def test_unauthorized_discovered_device_is_rejected(db_session, lab_with_broker_settings) -> None:
    """Discovered devices with unauthorized IPs are strictly rejected."""
    _seed_device(db_session, "ESP32-01", "10.32.252.105")
    _seed_device(db_session, "ROGUE-DEVICE", "10.32.252.200")

    assets = get_authorized_iot_assets(db_session, lab_with_broker_settings)
    asset_ids = {a.asset_id for a in assets}

    assert "ESP32-01" in asset_ids
    assert "ROGUE-DEVICE" not in asset_ids


def test_dynamic_scaling_n_devices_and_n_infrastructure(db_session, phase1_settings) -> None:
    """Dynamic scaling: supports N devices + N infrastructure assets without hardcoded counts."""
    custom_settings = Settings(
        _env_file=None,
        DATABASE_URL=phase1_settings.database_url,
        ASSESSMENT_ALLOWED_TARGETS="10.32.252.101,10.32.252.102,10.32.252.103,10.32.252.85,10.32.252.1",
        MQTT_BROKER_HOST="10.32.252.85",
        ASSESSMENT_PORTS="1883",
    )
    _seed_device(db_session, "ESP32-01", "10.32.252.101", device_type="ESP32")
    _seed_device(db_session, "ESP32-02", "10.32.252.102", device_type="ESP32")
    _seed_device(db_session, "ESP32-03", "10.32.252.103", device_type="ESP32")
    # Additional infrastructure registered in inventory
    _seed_device(db_session, "IOT-GATEWAY", "10.32.252.1", device_type="GATEWAY")

    assets = get_authorized_iot_assets(db_session, custom_settings)
    assert len(assets) == 5

    devices = [a for a in assets if a.asset_category == "IOT_DEVICE"]
    infra = [a for a in assets if a.asset_category == "IOT_INFRASTRUCTURE"]

    assert len(devices) == 3
    assert len(infra) == 2  # IOT-GATEWAY and MQTT-BROKER
    assert {d.asset_id for d in devices} == {"ESP32-01", "ESP32-02", "ESP32-03"}
    assert {i.asset_id for i in infra} == {"IOT-GATEWAY", "MQTT-BROKER"}


def test_evidence_and_finding_ownership_broker_vs_devices(
    db_session, lab_with_broker_settings, mock_probes
) -> None:
    """MQTT findings must strictly belong to the broker (10.32.252.85) and never to ESP32 devices."""
    _seed_device(db_session, "ESP32-01", "10.32.252.105")
    _seed_device(db_session, "ESP32-02", "10.32.252.57")

    result = run_environment_assessment(db_session, lab_with_broker_settings, probes=mock_probes)

    assert result.status == "COMPLETE"
    assert result.assessment_type == "ENVIRONMENT"

    # Verify posture contains separate device and infrastructure counts
    posture = result.metadata.get("posture", {})
    assert posture["assets_assessed"] == 3
    assert posture["assets_completed"] == 3
    assert posture["devices_assessed"] == 2
    assert posture["infrastructure_assessed"] == 1
    assert posture["highest_risk_asset"] == "MQTT-BROKER"

    # All findings must belong to 10.32.252.85 (Broker)
    broker_findings = [f for f in result.findings if f.target == "10.32.252.85"]
    esp_findings = [f for f in result.findings if f.target in ("10.32.252.105", "10.32.252.57")]

    assert len(broker_findings) > 0
    assert len(esp_findings) == 0  # ESP32s have closed ports, no fabricated findings!

    # Verify evidence ownership
    broker_evidence = [e for e in result.evidence if e.target == "10.32.252.85"]
    assert any(e.check_type == "MQTT_ANONYMOUS_CONNECT" for e in broker_evidence)
    assert not any(e.target != "10.32.252.85" and e.check_type == "MQTT_ANONYMOUS_CONNECT" for e in result.evidence)


def test_single_target_assessment_compatibility(
    db_session, lab_with_broker_settings, mock_probes
) -> None:
    """Existing single-target assessments for broker (10.32.252.85) and device (10.32.252.105) continue to work."""
    # Single target: Broker
    broker_result = run_assessment(db_session, lab_with_broker_settings, "10.32.252.85", probes=mock_probes)
    assert broker_result.status == "COMPLETE"
    assert broker_result.target == "10.32.252.85"
    assert len(broker_result.findings) > 0
    assert broker_result.highest_risk is not None

    # Single target: ESP32-01
    esp_result = run_assessment(db_session, lab_with_broker_settings, "10.32.252.105", probes=mock_probes)
    assert esp_result.status == "COMPLETE"
    assert esp_result.target == "10.32.252.105"
    assert len(esp_result.findings) == 0
    assert esp_result.highest_risk is None


def test_partial_failure_preserves_successful_assets(
    db_session, lab_with_broker_settings
) -> None:
    """One asset failing does not destroy successful assessments of other assets."""
    _seed_device(db_session, "ESP32-01", "10.32.252.105")
    _seed_device(db_session, "ESP32-02", "10.32.252.57")

    def failing_scan(target: str, ports: list[int], *, nmap_path: str, timeout_seconds: int) -> NmapScanResult:
        if target == "10.32.252.57":
            raise NmapError("Simulated probe network timeout for target 10.32.252.57")
        return _mock_scan(target, ports, nmap_path=nmap_path, timeout_seconds=timeout_seconds)

    failing_probes = AssessmentProbes(
        nmap=failing_scan,
        mqtt=_mock_mqtt,
        http=_not_called,
        tls=_mock_tls,
    )

    result = run_environment_assessment(db_session, lab_with_broker_settings, probes=failing_probes)

    assert result.status == "INCOMPLETE"
    assert "2 of 3 assets assessed successfully; 1 asset assessment(s) failed" in (result.error_summary or "")
    posture = result.metadata.get("posture", {})
    assert posture["assets_assessed"] == 3
    assert posture["assets_completed"] == 2
    assert posture["assets_failed"] == 1
    assert posture["devices_completed"] == 1
    assert posture["devices_failed"] == 1
    assert posture["infrastructure_completed"] == 1


def test_environment_no_findings_has_null_risk_not_zero_low(db_session, lab_settings) -> None:
    """When devices have no open ports and zero findings, risk must be null/None, NOT a synthetic 0 LOW."""
    _seed_device(db_session, "ESP32-01", "10.32.252.105")
    _seed_device(db_session, "ESP32-02", "10.32.252.57")

    def clean_scan(target: str, ports: list[int], *, nmap_path: str, timeout_seconds: int) -> NmapScanResult:
        return NmapScanResult(
            target=target,
            host_state="up",
            nmap_version="test",
            args="mocked",
            ports=[
                PortObservation(port=1883, protocol="tcp", state="closed", reason="conn-refused"),
            ],
        )

    clean_probes = AssessmentProbes(
        nmap=clean_scan,
        mqtt=_not_called,
        http=_not_called,
        tls=_not_called,
    )

    result = run_environment_assessment(db_session, lab_settings, probes=clean_probes)

    assert result.status == "COMPLETE"
    assert len(result.findings) == 0
    assert result.highest_risk is None
    assert result.highest_risk_level is None

    snapshots = db_session.execute(
        text("SELECT * FROM risk_snapshots WHERE assessment_id = :aid"),
        {"aid": result.id},
    ).mappings().all()
    assert len(snapshots) == 0
