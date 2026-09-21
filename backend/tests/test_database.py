"""Database integration tests for schema, constraints, and seed data."""

from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy import inspect, select, text

from app.models import Device, Finding, RiskFactorValue, RiskScore, User


EXPECTED_TABLES = {
    "users",
    "audit_logs",
    "devices",
    "device_interfaces",
    "scan_sessions",
    "ports",
    "services",
    "scan_services",
    "vulnerabilities",
    "findings",
    "cves",
    "finding_cves",
    "risk_scores",
    "risk_factors",
    "risk_factor_values",
    "risk_history",
    "risk_level_thresholds",
    "ml_models",
    "ml_predictions",
    "ai_explanations",
    "remediation_actions",
    "finding_remediations",
    "experiments",
    "experiment_results",
}


def test_database_connection(engine) -> None:
    with engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar() == 1


def test_all_tables_exist(engine) -> None:
    table_names = set(inspect(engine).get_table_names())
    missing = EXPECTED_TABLES - table_names
    assert not missing, f"Missing tables: {sorted(missing)}"


def test_foreign_keys_exist(engine) -> None:
    inspector = inspect(engine)
    fk_tables = {
        table
        for table in EXPECTED_TABLES
        if inspector.get_foreign_keys(table)
    }
    assert "findings" in fk_tables
    assert "risk_factor_values" in fk_tables


def test_seed_admin_user_exists(db_session) -> None:
    user = db_session.scalar(select(User).where(User.username == "admin"))
    assert user is not None
    assert user.password_hash != "ChangeMe123!"
    assert user.role == "ADMIN"


def test_seed_devices_exist(db_session) -> None:
    devices = db_session.scalars(select(Device)).all()
    assert len(devices) >= 6
    names = {device.device_name for device in devices}
    assert "ESP32-02" in names


def test_esp32_02_risk_score_and_factors(db_session) -> None:
    device = db_session.scalar(select(Device).where(Device.device_name == "ESP32-02"))
    assert device is not None
    assert str(device.ip_address) == "192.168.1.22"

    risk_score = db_session.scalar(
        select(RiskScore)
        .where(RiskScore.device_id == device.id)
        .order_by(RiskScore.calculated_at.desc())
    )
    assert risk_score is not None
    assert risk_score.score == Decimal("76.00")
    assert risk_score.risk_level == "HIGH"

    factor_values = db_session.scalars(
        select(RiskFactorValue).where(RiskFactorValue.risk_score_id == risk_score.id)
    ).all()
    total_contribution = sum(value.contribution for value in factor_values)
    assert total_contribution == Decimal("76.000")
    assert len(factor_values) == 5


def test_esp32_02_findings_exist(db_session) -> None:
    device = db_session.scalar(select(Device).where(Device.device_name == "ESP32-02"))
    findings = db_session.scalars(select(Finding).where(Finding.device_id == device.id)).all()
    titles = {finding.title for finding in findings}
    assert "MQTT without TLS" in titles
    assert "Weak authentication" in titles
    assert "HTTP enabled" in titles


def test_score_constraint_rejects_invalid_value(db_session) -> None:
    device = db_session.scalar(select(Device).where(Device.device_name == "ESP32-01"))
    invalid = RiskScore(
        device_id=device.id,
        score=Decimal("150.00"),
        risk_level="CRITICAL",
        score_version="TEST",
        calculation_method="RULE_BASED",
        calculated_at=device.updated_at,
    )
    db_session.add(invalid)
    with pytest.raises(Exception):
        db_session.commit()
    db_session.rollback()
