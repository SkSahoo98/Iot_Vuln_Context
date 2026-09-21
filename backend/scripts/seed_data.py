"""Development seed data for the IoT Security Framework database.

All data is synthetic and clearly marked for lab/demo use only.
No fake CVE identifiers are inserted.

Run after migrations:

    python scripts/seed_data.py
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from passlib.context import CryptContext
from sqlalchemy import select

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.database import SessionLocal  # noqa: E402
from app.models import (  # noqa: E402
    AIExplanation,
    Device,
    DeviceInterface,
    Finding,
    MLModel,
    MLPrediction,
    Port,
    RemediationAction,
    RiskFactor,
    RiskFactorValue,
    RiskHistory,
    RiskLevelThreshold,
    RiskScore,
    ScanService,
    ScanSession,
    Service,
    User,
    Vulnerability,
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
NOW = datetime.now(UTC)
SCORE_VERSION = "IDRS-1.0.0"


def seed_risk_level_thresholds(session) -> None:
    if session.scalar(select(RiskLevelThreshold).limit(1)):
        return

    bands = [
        ("LOW", Decimal("0"), Decimal("20")),
        ("MODERATE", Decimal("21"), Decimal("40")),
        ("MEDIUM", Decimal("41"), Decimal("60")),
        ("HIGH", Decimal("61"), Decimal("80")),
        ("CRITICAL", Decimal("81"), Decimal("100")),
    ]
    for level_name, min_score, max_score in bands:
        session.add(
            RiskLevelThreshold(
                score_version=SCORE_VERSION,
                level_name=level_name,
                min_score=min_score,
                max_score=max_score,
                is_active=True,
            )
        )


def seed_risk_factors(session) -> dict[str, RiskFactor]:
    existing = {
        factor.factor_code: factor
        for factor in session.scalars(select(RiskFactor)).all()
    }
    if existing:
        return existing

    definitions = [
        ("MQTT_SECURITY", "MQTT Security", Decimal("25"), Decimal("25")),
        ("AUTHENTICATION_SECURITY", "Authentication Security", Decimal("20"), Decimal("20")),
        ("NETWORK_EXPOSURE", "Network Exposure", Decimal("15"), Decimal("15")),
        ("FIRMWARE_AGE", "Firmware Age", Decimal("10"), Decimal("10")),
        ("DEVICE_CRITICALITY", "Device Criticality", Decimal("10"), Decimal("10")),
        ("PROTOCOL_SECURITY", "Protocol Security", Decimal("15"), Decimal("15")),
        ("ENCRYPTION_SECURITY", "Encryption Security", Decimal("20"), Decimal("20")),
        ("ATTACK_SURFACE", "Attack Surface", Decimal("15"), Decimal("15")),
        ("MANAGEMENT_EXPOSURE", "Management Exposure", Decimal("15"), Decimal("15")),
        ("KNOWN_CVES", "Known CVEs", Decimal("20"), Decimal("20")),
    ]
    factors: dict[str, RiskFactor] = {}
    for code, name, weight, max_contrib in definitions:
        factor = RiskFactor(
            factor_code=code,
            factor_name=name,
            description=f"Synthetic catalog factor: {name}",
            category="IOT_SECURITY",
            default_weight=weight,
            max_contribution=max_contrib,
            is_active=True,
        )
        session.add(factor)
        factors[code] = factor
    session.flush()
    return factors


def seed_vulnerabilities(session) -> dict[str, Vulnerability]:
    existing = {
        item.vulnerability_code: item
        for item in session.scalars(select(Vulnerability)).all()
    }
    if existing:
        return existing

    catalog = [
        ("INSECURE_MQTT", "MQTT without TLS", "HIGH", "PROTOCOL"),
        ("WEAK_AUTHENTICATION", "Weak authentication", "HIGH", "AUTH"),
        ("UNENCRYPTED_HTTP", "HTTP enabled without encryption", "MEDIUM", "PROTOCOL"),
        ("TELNET_ENABLED", "Telnet service enabled", "HIGH", "PROTOCOL"),
        ("WEAK_TLS", "Weak TLS configuration", "HIGH", "TLS"),
        ("OUTDATED_FIRMWARE", "Outdated firmware", "MEDIUM", "FIRMWARE"),
        ("EXPOSED_MANAGEMENT_INTERFACE", "Exposed management interface", "HIGH", "EXPOSURE"),
    ]
    result: dict[str, Vulnerability] = {}
    for code, title, severity, category in catalog:
        vuln = Vulnerability(
            vulnerability_code=code,
            title=title,
            description=f"Synthetic IoT configuration weakness: {title}",
            severity=severity,
            category=category,
            source="SYNTHETIC",
            published_at=NOW,
        )
        session.add(vuln)
        result[code] = vuln
    session.flush()
    return result


def seed_remediations(session) -> dict[str, RemediationAction]:
    existing = {item.title: item for item in session.scalars(select(RemediationAction)).all()}
    if existing:
        return existing

    actions = [
        ("Enable MQTT TLS", "Configure the MQTT broker and device to use TLS on port 8883.", "PROTOCOL", "HIGH"),
        ("Enable MQTT authentication", "Require username/password or certificate-based MQTT authentication.", "AUTH", "HIGH"),
        ("Disable HTTP or enforce HTTPS", "Remove plain HTTP or redirect all traffic to HTTPS.", "PROTOCOL", "MEDIUM"),
        ("Disable Telnet", "Turn off Telnet and use SSH where remote shell access is required.", "PROTOCOL", "HIGH"),
        ("Update firmware", "Apply the latest vendor firmware with security patches.", "FIRMWARE", "MEDIUM"),
        ("Restrict management interface", "Bind management services to the lab VLAN only.", "EXPOSURE", "HIGH"),
    ]
    result: dict[str, RemediationAction] = {}
    for title, description, category, priority in actions:
        action = RemediationAction(
            title=title,
            description=description,
            category=category,
            priority=priority,
            estimated_effort="MEDIUM",
            verification_method="Re-scan the device and confirm the finding is mitigated.",
        )
        session.add(action)
        result[title] = action
    session.flush()
    return result


def seed_users(session) -> None:
    if session.scalar(select(User).where(User.username == "admin")):
        return

    session.add(
        User(
            username="admin",
            email="admin@iot-lab.local",
            password_hash=pwd_context.hash("ChangeMe123!"),
            role="ADMIN",
            is_active=True,
        )
    )


def get_or_create_port(session, port_number: int, protocol: str, service_name: str) -> Port:
    port = session.scalar(
        select(Port).where(Port.port_number == port_number, Port.protocol == protocol)
    )
    if port:
        return port
    port = Port(port_number=port_number, protocol=protocol, service_name=service_name)
    session.add(port)
    session.flush()
    return port


def get_or_create_service(session, service_name: str, default_port: int, protocol: str) -> Service:
    service = session.scalar(select(Service).where(Service.service_name == service_name))
    if service:
        return service
    service = Service(
        service_name=service_name,
        default_port=default_port,
        protocol=protocol,
        description=f"Synthetic catalog entry for {service_name}",
    )
    session.add(service)
    session.flush()
    return service


def seed_devices(session) -> list[Device]:
    if session.scalar(select(Device).limit(1)):
        return list(session.scalars(select(Device)).all())

    device_specs = [
        ("ESP32-01", "ESP32", "192.168.1.21", "AA:BB:CC:DD:EE:01", "1.0.0", "MEDIUM"),
        ("ESP32-02", "ESP32", "192.168.1.22", "AA:BB:CC:DD:EE:02", "1.0.0", "HIGH"),
        ("ESP32-03", "ESP32", "192.168.1.23", "AA:BB:CC:DD:EE:03", "1.1.0", "MEDIUM"),
        ("RPI-GATEWAY-01", "RASPBERRY_PI", "192.168.1.10", "AA:BB:CC:DD:EE:10", "2026.1", "HIGH"),
        ("TEMP-SENSOR-01", "SENSOR", "192.168.1.31", "AA:BB:CC:DD:EE:31", "0.9.2", "LOW"),
        ("SMART-CAMERA-01", "CAMERA", "192.168.1.40", "AA:BB:CC:DD:EE:40", "2.4.1", "HIGH"),
        ("LAB-GATEWAY-01", "GATEWAY", "192.168.1.5", "AA:BB:CC:DD:EE:05", "3.0.0", "CRITICAL"),
    ]

    devices: list[Device] = []
    for name, device_type, ip, mac, firmware, criticality in device_specs:
        device = Device(
            device_name=name,
            device_type=device_type,
            manufacturer="SyntheticLab",
            model=f"{device_type}-DEMO",
            firmware_version=firmware,
            ip_address=ip,
            hostname=name.lower().replace("_", "-"),
            mac_address=mac,
            criticality=criticality,
            network_zone="IOT_LAB",
            description="Synthetic authorized lab device for development only.",
            is_active=True,
            first_seen=NOW,
            last_seen=NOW,
        )
        session.add(device)
        session.flush()
        session.add(
            DeviceInterface(
                device_id=device.id,
                interface_name="wlan0",
                interface_type="WIFI",
                mac_address=mac,
                ipv4=ip,
                is_active=True,
            )
        )
        devices.append(device)
    return devices


def seed_esp32_02_demo(
    session,
    devices: list[Device],
    vulnerabilities: dict[str, Vulnerability],
    remediations: dict[str, RemediationAction],
    factors: dict[str, RiskFactor],
) -> None:
    esp32_02 = next(device for device in devices if device.device_name == "ESP32-02")
    if session.scalar(select(ScanSession).where(ScanSession.device_id == esp32_02.id).limit(1)):
        return

    scan = ScanSession(
        device_id=esp32_02.id,
        scanner="NMAP",
        scan_type="FULL_ASSESSMENT",
        started_at=NOW,
        completed_at=NOW,
        status="COMPLETED",
        target="192.168.1.22",
        configuration={"source": "SYNTHETIC", "authorized_lab_only": True},
    )
    session.add(scan)
    session.flush()

    mqtt_port = get_or_create_port(session, 1883, "TCP", "mqtt")
    http_port = get_or_create_port(session, 80, "TCP", "http")
    mqtt_service = get_or_create_service(session, "mqtt", 1883, "TCP")
    http_service = get_or_create_service(session, "http", 80, "TCP")

    mqtt_obs = ScanService(
        scan_session_id=scan.id,
        port_id=mqtt_port.id,
        service_id=mqtt_service.id,
        service_name="mqtt",
        service_version="2.x",
        product_name="Mosquitto",
        banner="MQTT broker detected (synthetic)",
        state="OPEN",
        confidence=Decimal("0.95"),
        detected_at=NOW,
    )
    http_obs = ScanService(
        scan_session_id=scan.id,
        port_id=http_port.id,
        service_id=http_service.id,
        service_name="http",
        service_version="1.1",
        product_name="ESP32 HTTP",
        banner="HTTP service detected (synthetic)",
        state="OPEN",
        confidence=Decimal("0.90"),
        detected_at=NOW,
    )
    session.add_all([mqtt_obs, http_obs])
    session.flush()

    finding_specs = [
        (
            "MQTT without TLS",
            "INSECURE_MQTT",
            "HIGH",
            mqtt_obs,
            {"port": 1883, "service": "mqtt", "tls": False, "authentication": False, "source": "SYNTHETIC"},
            "Enable MQTT TLS",
        ),
        (
            "Weak authentication",
            "WEAK_AUTHENTICATION",
            "HIGH",
            mqtt_obs,
            {"service": "mqtt", "authentication": "weak", "source": "SYNTHETIC"},
            "Enable MQTT authentication",
        ),
        (
            "HTTP enabled",
            "UNENCRYPTED_HTTP",
            "MEDIUM",
            http_obs,
            {"port": 80, "service": "http", "tls": False, "source": "SYNTHETIC"},
            "Disable HTTP or enforce HTTPS",
        ),
    ]

    created_findings: list[Finding] = []
    for title, vuln_code, severity, scan_service, evidence, remediation_title in finding_specs:
        finding = Finding(
            device_id=esp32_02.id,
            scan_session_id=scan.id,
            scan_service_id=scan_service.id,
            vulnerability_id=vulnerabilities[vuln_code].id,
            finding_type="CONFIGURATION",
            title=title,
            description=f"Synthetic finding for authorized lab device {esp32_02.device_name}.",
            severity=severity,
            confidence=Decimal("0.95"),
            status="OPEN",
            evidence=evidence,
            impact="Unauthorized actors on the lab network could observe or manipulate device traffic.",
            recommendation=remediation_title,
            first_detected=NOW,
            last_detected=NOW,
        )
        finding.remediation_actions.append(remediations[remediation_title])
        session.add(finding)
        created_findings.append(finding)
    session.flush()

    risk_score = RiskScore(
        device_id=esp32_02.id,
        scan_session_id=scan.id,
        score=Decimal("76.00"),
        risk_level="HIGH",
        score_version=SCORE_VERSION,
        model_version=None,
        calculation_method="RULE_BASED",
        confidence=Decimal("0.92"),
        calculated_at=NOW,
    )
    session.add(risk_score)
    session.flush()

    factor_contributions = [
        ("MQTT_SECURITY", Decimal("25"), Decimal("25"), "NO_TLS", created_findings[0].id),
        ("AUTHENTICATION_SECURITY", Decimal("20"), Decimal("20"), "WEAK_AUTH", created_findings[1].id),
        ("NETWORK_EXPOSURE", Decimal("15"), Decimal("15"), "LAB_LAN", None),
        ("FIRMWARE_AGE", Decimal("8"), Decimal("8"), "1.0.0", None),
        ("DEVICE_CRITICALITY", Decimal("8"), Decimal("8"), "HIGH", None),
    ]
    for code, weight, contribution, raw_value, finding_id in factor_contributions:
        session.add(
            RiskFactorValue(
                risk_score_id=risk_score.id,
                risk_factor_id=factors[code].id,
                finding_id=finding_id,
                raw_value=raw_value,
                normalized_value=Decimal("1.0"),
                weight=weight,
                contribution=contribution,
                evidence={"source": "SYNTHETIC"},
            )
        )

    session.add(
        RiskHistory(
            device_id=esp32_02.id,
            risk_score_id=risk_score.id,
            previous_score=Decimal("78.00"),
            new_score=Decimal("76.00"),
            previous_level="HIGH",
            new_level="HIGH",
            change_reason="Synthetic initial assessment recorded for ESP32-02.",
            changed_at=NOW,
        )
    )

    ml_model = MLModel(
        model_name="risk_prioritizer_rf",
        algorithm="RandomForest",
        version="0.1.0-synthetic",
        dataset_version="synthetic-v1",
        features={"mqtt_tls": False, "auth_strength": "weak", "open_ports": 2},
        metrics={"note": "synthetic demo only"},
        model_path="ml/models/.gitkeep",
        training_date=NOW,
        status="DEMO",
    )
    session.add(ml_model)
    session.flush()

    prediction = MLPrediction(
        device_id=esp32_02.id,
        scan_session_id=scan.id,
        ml_model_id=ml_model.id,
        risk_score_id=risk_score.id,
        predicted_class="HIGH",
        predicted_score=Decimal("76.00"),
        confidence=Decimal("0.88"),
        features={"mqtt_tls": False, "http_enabled": True, "source": "SYNTHETIC"},
        prediction_timestamp=NOW,
    )
    session.add(prediction)
    session.flush()

    session.add(
        AIExplanation(
            device_id=esp32_02.id,
            risk_score_id=risk_score.id,
            ml_prediction_id=prediction.id,
            explanation_type="RULE_BASED",
            summary="ESP32-02 is HIGH risk primarily because MQTT lacks TLS and authentication is weak.",
            top_factors={
                "MQTT_SECURITY": 25,
                "AUTHENTICATION_SECURITY": 20,
                "NETWORK_EXPOSURE": 15,
            },
            explanation_data={"source": "SYNTHETIC", "score_version": SCORE_VERSION},
            generated_at=NOW,
        )
    )


def main() -> None:
    session = SessionLocal()
    try:
        seed_users(session)
        seed_risk_level_thresholds(session)
        factors = seed_risk_factors(session)
        vulnerabilities = seed_vulnerabilities(session)
        remediations = seed_remediations(session)
        devices = seed_devices(session)
        seed_esp32_02_demo(session, devices, vulnerabilities, remediations, factors)
        session.commit()
        print("Seed data inserted successfully.")
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
