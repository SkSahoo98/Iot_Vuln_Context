
"""Automated security tests for production read-only protection and Cloud boundaries.

Ensures write operations are blocked when READ_ONLY_MODE=true, active network scanning
remains blocked when ASSESSMENT_ALLOWED_TARGETS is empty, and read endpoints + assistant
explanations remain available.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from datetime import datetime, timezone
from unittest import mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.main import app
from app.schemas.api import DeviceOut
from app.schemas.assessment import AssessmentSummaryOut
from app.schemas.assistant import AssistantExplainResponse
from app.schemas.remediation import RemediationWorkflowOut


@pytest.fixture(scope="session", autouse=True)
def require_database() -> Generator[None, None, None]:
    """Override tests/conftest.py session fixture so tests run completely offline."""
    yield


@pytest.fixture
def mock_db() -> mock.MagicMock:
    return mock.MagicMock(spec=Session)


class TestProductionSecurity:
    """Security boundaries and read-only protections for Vercel production deployment."""

    def test_read_only_mode_blocks_remediation_creation(self, mock_db: mock.MagicMock) -> None:
        """POST /api/v1/remediations must return 403 when READ_ONLY_MODE=true."""
        settings = Settings(read_only_mode=True)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        try:
            client = TestClient(app)
            payload = {
                "baseline_assessment_id": str(uuid4()),
                "baseline_finding_id": str(uuid4()),
            }
            resp = client.post("/api/v1/remediations", json=payload)
            assert resp.status_code == 403
            assert "Write operations are disabled in production demo mode" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    def test_read_only_mode_blocks_remediation_confirmation(self, mock_db: mock.MagicMock) -> None:
        """POST /api/v1/remediations/{id}/confirm must return 403 when READ_ONLY_MODE=true."""
        settings = Settings(read_only_mode=True)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        try:
            client = TestClient(app)
            workflow_id = str(uuid4())
            payload = {"notes": "Applied firewall rule"}
            resp = client.post(f"/api/v1/remediations/{workflow_id}/confirm", json=payload)
            assert resp.status_code == 403
            assert "Write operations are disabled in production demo mode" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    def test_get_devices_still_works_in_read_only_mode(self, mock_db: mock.MagicMock) -> None:
        """GET /api/v1/devices must remain accessible in read-only mode."""
        settings = Settings(read_only_mode=True)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        with mock.patch("app.api.v1.list_devices", return_value=[]):
            try:
                client = TestClient(app)
                resp = client.get("/api/v1/devices")
                assert resp.status_code == 200
                assert resp.json() == []
            finally:
                app.dependency_overrides.clear()

    def test_get_assessments_still_works_in_read_only_mode(self, mock_db: mock.MagicMock) -> None:
        """GET /api/v1/assessments must remain accessible in read-only mode."""
        settings = Settings(read_only_mode=True)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        with mock.patch("app.api.v1.list_assessments", return_value=[]):
            try:
                client = TestClient(app)
                resp = client.get("/api/v1/assessments")
                assert resp.status_code == 200
                assert resp.json() == []
            finally:
                app.dependency_overrides.clear()

    def test_get_remediations_still_works_in_read_only_mode(self, mock_db: mock.MagicMock) -> None:
        """GET /api/v1/remediations must remain accessible in read-only mode."""
        settings = Settings(read_only_mode=True)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        with mock.patch("app.api.v1.list_remediations", return_value=[]):
            try:
                client = TestClient(app)
                resp = client.get("/api/v1/remediations")
                assert resp.status_code == 200
                assert resp.json() == []
            finally:
                app.dependency_overrides.clear()

    def test_assistant_explain_post_remains_available(self, mock_db: mock.MagicMock) -> None:
        """POST /api/v1/assistant/explain is a query endpoint and must not be blocked by read_only_mode."""
        settings = Settings(read_only_mode=True)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        mock_response = AssistantExplainResponse(
            status="COMPLETE",
            answer="Grounded explanation: MQTT service exposed without TLS.",
            source="DETERMINISTIC_FALLBACK",
            basis=["RISK_RESULT", "FINDINGS"],
        )

        with mock.patch("app.api.v1.explain_for_assistant", return_value=mock_response):
            try:
                client = TestClient(app)
                payload = {"intent": "SUMMARY"}
                resp = client.post("/api/v1/assistant/explain", json=payload)
                assert resp.status_code == 200
                assert resp.json()["status"] == "COMPLETE"
                assert resp.json()["answer"] == "Grounded explanation: MQTT service exposed without TLS."
            finally:
                app.dependency_overrides.clear()

    def test_assessment_post_blocked_when_allowlist_is_empty(self, mock_db: mock.MagicMock) -> None:
        """POST /api/v1/assessments must return 403 when ASSESSMENT_ALLOWED_TARGETS is empty."""
        settings = Settings(assessment_allowed_targets="")
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        try:
            client = TestClient(app)
            payload = {"target": "192.168.1.101"}
            resp = client.post("/api/v1/assessments", json=payload)
            assert resp.status_code == 403
            assert "ASSESSMENT_ALLOWED_TARGETS" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    def test_remediation_verify_post_blocked_when_allowlist_is_empty(self, mock_db: mock.MagicMock) -> None:
        """POST /api/v1/remediations/{id}/verify must return 403 when target is outside allowlist."""
        settings = Settings(assessment_allowed_targets="")
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        mock_wf = mock.MagicMock(spec=RemediationWorkflowOut)
        mock_wf.target = "192.168.1.101"
        mock_wf.status = "READY_FOR_VERIFICATION"
        mock_finding_id = uuid4()
        mock_wf.baseline_finding_id = mock_finding_id
        mock_wf.baseline_assessment_id = uuid4()

        mock_finding = mock.MagicMock()
        mock_finding.id = mock_finding_id
        mock_baseline_assessment = mock.MagicMock()
        mock_baseline_assessment.findings = [mock_finding]

        with mock.patch("app.services.remediation_service.get_remediation", return_value=mock_wf), \
             mock.patch("app.services.remediation_service.get_assessment", return_value=mock_baseline_assessment), \
             mock.patch("scanner.network_checks.nmap_scanner.run_nmap") as mock_nmap, \
             mock.patch("app.services.remediation_service.run_assessment") as mock_run_assessment:
            try:
                client = TestClient(app)
                workflow_id = str(uuid4())
                payload = {"explicit_approval": True}
                resp = client.post(f"/api/v1/remediations/{workflow_id}/verify", json=payload)
                assert resp.status_code == 403
                assert "ASSESSMENT_ALLOWED_TARGETS" in resp.json()["detail"]
                mock_nmap.assert_not_called()
                mock_run_assessment.assert_not_called()
            finally:
                app.dependency_overrides.clear()

    def test_read_only_mode_false_preserves_local_development(self, mock_db: mock.MagicMock) -> None:
        """When READ_ONLY_MODE=false, write operations pass through without read-only rejection."""
        settings = Settings(read_only_mode=False)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_db] = lambda: mock_db

        now = datetime.now(timezone.utc)
        mock_wf = mock.MagicMock(spec=RemediationWorkflowOut)
        mock_wf.id = uuid4()
        mock_wf.status = "PROPOSED"
        mock_wf.target = "192.168.1.101"
        mock_wf.finding_fingerprint = "fp"
        mock_wf.guidance_version = "v1"
        mock_wf.guidance_steps = []
        mock_wf.verification_requirements = []
        mock_wf.coverage_summary = {}
        mock_wf.baseline_assessment_id = uuid4()
        mock_wf.baseline_finding_id = uuid4()
        mock_wf.user_confirmed_at = None
        mock_wf.verification_assessment_id = None
        mock_wf.verification_verdict = None
        mock_wf.verification_evidence_ids = []
        mock_wf.created_at = now
        mock_wf.updated_at = now

        with mock.patch("app.api.v1.create_or_get_remediation", return_value=mock_wf):
            try:
                client = TestClient(app)
                payload = {
                    "baseline_assessment_id": str(uuid4()),
                    "baseline_finding_id": str(uuid4()),
                }
                resp = client.post("/api/v1/remediations", json=payload)
                assert resp.status_code == 201
            finally:
                app.dependency_overrides.clear()

    def test_health_reports_production_read_only_capabilities(self) -> None:
        """GET /api/v1/health must report read-only mode and disabled active assessment in production."""
        settings = Settings(
            environment="production",
            read_only_mode=True,
            assessment_allowed_targets="",
        )
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            client = TestClient(app)
            resp = client.get("/api/v1/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["service"] == "iot-security-framework"
            assert data["environment"] == "production"
            assert data["read_only_mode"] is True
            assert data["active_assessment_supported"] is False
        finally:
            app.dependency_overrides.clear()

    def test_health_reports_local_lab_capabilities(self) -> None:
        """GET /api/v1/health must report active assessment supported in local lab with allowlist."""
        settings = Settings(
            environment="development",
            read_only_mode=False,
            assessment_allowed_targets="10.32.252.105,10.32.252.57,10.32.252.85",
        )
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            client = TestClient(app)
            resp = client.get("/api/v1/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["service"] == "iot-security-framework"
            assert data["environment"] == "development"
            assert data["read_only_mode"] is False
            assert data["active_assessment_supported"] is True
        finally:
            app.dependency_overrides.clear()

    def test_health_reports_local_lab_without_allowlist(self) -> None:
        """GET /api/v1/health must report active assessment not supported if allowlist is empty."""
        settings = Settings(
            environment="development",
            read_only_mode=False,
            assessment_allowed_targets="",
        )
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            client = TestClient(app)
            resp = client.get("/api/v1/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["read_only_mode"] is False
            assert data["active_assessment_supported"] is False
        finally:
            app.dependency_overrides.clear()
