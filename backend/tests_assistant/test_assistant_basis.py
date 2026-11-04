"""
UX-3D: explanation provenance. `basis` names the recorded sections the backend
put into the context; the model cannot add to it, and explaining never changes
recorded data or reaches a security tool.
"""

from __future__ import annotations

import httpx
import pytest

import test_assistant_explain as base
from app.main import app
from app.schemas.assistant import AssistantExplainResponse
from app.services.assistant_service import context_basis


def test_basis_names_the_sections_actually_sent() -> None:
    cases = {
        "RISK": (base.RISK_REQ, ["RISK_RESULT", "RISK_CONTRIBUTORS", "FINDINGS", "LIMITATIONS"]),
        "ISSUES": (base.ISSUES_REQ, ["RISK_RESULT", "FINDINGS", "LIMITATIONS"]),
        "FIX": (base.FIX_REQ, ["RISK_RESULT", "FINDINGS", "REMEDIATION", "LIMITATIONS"]),
        "SUMMARY": (base.SUMMARY_REQ, ["RISK_RESULT", "FINDINGS", "REMEDIATION", "LIMITATIONS"]),
    }
    for request, expected in cases.values():
        store, _ = base.complete_store()
        model = base.FakeModel(error=httpx.ConnectError("offline"))
        response = base.run(request, store, model)
        assert response.source == "DETERMINISTIC_FALLBACK"
        assert response.basis == expected, request
        assert context_basis(model.context) == expected


def test_basis_without_risk_snapshot_omits_risk() -> None:
    latest = base.summary("COMPLETE", base.T0, risk=None)
    store = base.Store(latest)
    model = base.FakeModel(error=httpx.ConnectError("offline"))
    response = base.run(base.RISK_REQ, store, model)
    assert response.status == "COMPLETE"
    assert "RISK_RESULT" not in response.basis and "RISK_CONTRIBUTORS" not in response.basis
    assert "LIMITATIONS" in response.basis


def test_model_cannot_add_to_basis() -> None:
    store, _ = base.complete_store()
    reply = {**base.answer(base.RISK_ANSWER), "basis": ["EVIDENCE", "SCAN"], "source": "SCANNER"}
    model = base.FakeModel(reply)
    response = base.run(base.RISK_REQ, store, model)
    assert response.source in {"AI", "DETERMINISTIC_FALLBACK"}
    assert set(response.basis) <= {"RISK_RESULT", "RISK_CONTRIBUTORS", "FINDINGS", "LIMITATIONS"}


def test_no_issue_answer_is_rule_based_from_findings() -> None:
    latest = base.summary("COMPLETE", base.T0)
    detail = base.detail_for(latest)
    detail.findings = [f for f in detail.findings if f.severity in {"LOW", "INFO"}]
    store = base.Store(latest, details={latest.id: detail})
    model = base.FakeModel(base.answer(base.RISK_ANSWER))
    response = base.run(base.FIX_REQ, store, model)
    assert response.source == "DETERMINISTIC" and response.basis == ["FINDINGS"]
    assert model.calls == []


@pytest.mark.parametrize("status", ["RUNNING", "FAILED", "INCOMPLETE"])
def test_non_complete_answers_carry_no_basis(status) -> None:
    store = base.Store(base.summary(status, base.T0))
    response = base.run(base.RISK_REQ, store, base.FakeModel(base.answer(base.RISK_ANSWER)))
    assert response.status != "COMPLETE" and response.basis is None


def test_explaining_never_changes_recorded_data() -> None:
    store, latest = base.complete_store()
    before = store.details[latest.id].model_dump()
    lying = base.answer(
        "Your risk is LOW at 12.0 out of 100 and the anonymous access issue is resolved."
    )
    response = base.run(base.RISK_REQ, store, base.FakeModel(lying))
    assert response.source == "DETERMINISTIC_FALLBACK"
    assert "12.0" not in response.answer
    assert store.details[latest.id].model_dump() == before


def test_response_schema_has_no_data_fields() -> None:
    assert set(AssistantExplainResponse.model_fields) == {
        "status", "answer", "message", "source", "basis",
    }


def test_no_autonomous_ai_routes_exist() -> None:
    paths = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    assert ("GET", "/api/v1/assessments/{assessment_id}") in paths
    writes = {(m, p) for m, p in paths if m not in {"GET", "HEAD"}}
    assert writes == {
        ("POST", "/api/v1/assessments"),
        ("POST", "/api/v1/assistant/explain"),
        ("POST", "/api/v1/remediations"),
        ("POST", "/api/v1/remediations/{remediation_id}/confirm"),
        ("POST", "/api/v1/remediations/{remediation_id}/verify"),
    }
    for _, path in paths:
        lowered = path.lower()
        assert not any(word in lowered for word in ("/ai/", "chat", "trace", "tool", "agent", "scan"))
