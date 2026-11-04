from __future__ import annotations

from fastapi.testclient import TestClient

import app.api.v1 as api_v1
from app.core.config import get_settings
from app.core.database import get_db
from app.main import app
from app.services.assessment_service import AssessmentProbes
from scanner.core.models import Evidence
from scanner.network_checks.nmap_scanner import NmapScanResult, PortObservation


def _responding_scan(
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
                port=22,
                protocol="tcp",
                state="closed",
                reason="conn-refused",
                service_name="ssh",
            )
        ],
    )


def _not_called(*args, **kwargs) -> Evidence:
    raise AssertionError("Specialized probe should not be called")


def test_assessment_post_list_and_detail_endpoints(
    db_session,
    phase1_settings,
    monkeypatch,
) -> None:
    probes = AssessmentProbes(
        nmap=_responding_scan,
        mqtt=_not_called,
        http=_not_called,
        tls=_not_called,
    )
    real_run = api_v1.run_assessment

    def run_with_mocked_network(db, settings, target):
        return real_run(db, settings, target, probes=probes)

    def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: phase1_settings
    monkeypatch.setattr(api_v1, "run_assessment", run_with_mocked_network)
    try:
        with TestClient(app) as client:
            created = client.post(
                "/api/v1/assessments",
                json={"target": "127.0.0.250"},
            )
            assert created.status_code == 201, created.text
            payload = created.json()
            assert payload["status"] == "COMPLETE"
            assessment_id = payload["id"]

            history = client.get("/api/v1/assessments")
            assert history.status_code == 200
            assert any(item["id"] == assessment_id for item in history.json())

            detail = client.get(f"/api/v1/assessments/{assessment_id}")
            assert detail.status_code == 200
            assert detail.json()["target"] == "127.0.0.250"
            assert detail.json()["evidence_count"] == 1
    finally:
        app.dependency_overrides.clear()


def test_assessment_endpoint_rejects_disallowed_target(
    db_session,
    phase1_settings,
) -> None:
    def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: phase1_settings
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/assessments",
                json={"target": "8.8.8.8"},
            )
        assert response.status_code == 403
        assert "not in ASSESSMENT_ALLOWED_TARGETS" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()
