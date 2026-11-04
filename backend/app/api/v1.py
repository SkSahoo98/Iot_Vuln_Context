"""API v1 routers."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentDetailOut,
    AssessmentSummaryOut,
)
from app.schemas.api import (
    AIExplanationOut,
    DeviceOut,
    ExperimentDetailOut,
    ExperimentSummaryOut,
    FindingOut,
    RiskSummaryOut,
)
from app.schemas.assistant import AssistantExplainRequest, AssistantExplainResponse
from app.services.ai_explanation import explain_finding
from app.services.assistant_service import explain_for_assistant
from app.services.assessment_service import (
    get_assessment,
    list_assessments,
    run_assessment,
)
from app.services.multi_device_coordinator import run_environment_assessment
from app.services.device_service import list_devices
from app.services.experiment_service import get_experiment, list_experiments
from app.services.finding_service import list_findings
from app.services.risk_service import assess_risk
from scanner.targets import TargetNotAllowedError


from app.schemas.remediation import (
    RemediationComparisonOut,
    RemediationConfirmRequest,
    RemediationVerifyRequest,
    RemediationWorkflowCreate,
    RemediationWorkflowOut,
)
from app.services.remediation_service import (
    confirm_remediation,
    create_or_get_remediation,
    get_remediation,
    get_remediation_comparison,
    list_remediations,
    verify_remediation,
)

router = APIRouter(prefix="/api/v1")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "iot-security-framework"}


@router.get("/devices", response_model=list[DeviceOut])
def get_devices(db: Session = Depends(get_db)) -> list[DeviceOut]:
    return list_devices(db)


@router.get("/findings", response_model=list[FindingOut])
def get_findings(settings: Settings = Depends(get_settings)) -> list[FindingOut]:
    return list_findings(settings)


@router.get("/risk", response_model=RiskSummaryOut)
def get_risk(settings: Settings = Depends(get_settings)) -> RiskSummaryOut:
    return assess_risk(settings)


@router.post(
    "/assessments",
    response_model=AssessmentDetailOut,
    status_code=201,
)
def create_assessment(
    request: AssessmentCreate,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AssessmentDetailOut:
    try:
        if (
            request.scope == "AUTHORIZED_IOT"
            or request.target in (None, "", "AUTHORIZED_IOT", "ALL_AUTHORIZED")
        ):
            return run_environment_assessment(
                db, settings, device_ids=request.device_ids
            )
        return run_assessment(db, settings, request.target)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Assessment configuration is invalid: {exc}",
        ) from exc


@router.get(
    "/assessments",
    response_model=list[AssessmentSummaryOut],
)
def get_assessments(
    db: Session = Depends(get_db),
) -> list[AssessmentSummaryOut]:
    return list_assessments(db)


@router.get(
    "/assessments/{assessment_id}",
    response_model=AssessmentDetailOut,
)
def get_assessment_detail(
    assessment_id: UUID,
    db: Session = Depends(get_db),
) -> AssessmentDetailOut:
    detail = get_assessment(db, assessment_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return detail


@router.post(
    "/assistant/explain",
    response_model=AssistantExplainResponse,
    response_model_exclude_none=True,
)
def assistant_explain(
    request: AssistantExplainRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AssistantExplainResponse:
    """Explain the latest COMPLETE assessment; read-only, no scanning."""
    return explain_for_assistant(request, db=db, settings=settings)


@router.get("/experiments", response_model=list[ExperimentSummaryOut])
def get_experiments(db: Session = Depends(get_db)) -> list[ExperimentSummaryOut]:
    return list_experiments(db)


@router.get("/experiments/{experiment_id}", response_model=ExperimentDetailOut)
def get_experiment_detail(
    experiment_id: UUID,
    db: Session = Depends(get_db),
) -> ExperimentDetailOut:
    detail = get_experiment(db, experiment_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return detail


@router.get("/explanations/{finding_type}", response_model=AIExplanationOut)
def get_explanation(
    finding_type: str,
    refresh: bool = False,
    settings: Settings = Depends(get_settings),
) -> AIExplanationOut:
    findings = list_findings(settings)
    risk = assess_risk(settings)
    finding = next(
        (item for item in findings if item.finding_type == finding_type),
        None,
    )
    if finding is None:
        raise HTTPException(
            status_code=404,
            detail=f"No evidence-backed finding for type '{finding_type}'",
        )
    risk_item = next(
        (item for item in risk.items if item.finding_type == finding_type),
        None,
    )
    return explain_finding(finding, risk_item, force_refresh=refresh)


@router.post(
    "/remediations",
    response_model=RemediationWorkflowOut,
    status_code=201,
)
def create_remediation_endpoint(
    request: RemediationWorkflowCreate,
    db: Session = Depends(get_db),
) -> RemediationWorkflowOut:
    try:
        return create_or_get_remediation(
            db,
            baseline_assessment_id=request.baseline_assessment_id,
            baseline_finding_id=request.baseline_finding_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/remediations",
    response_model=list[RemediationWorkflowOut],
)
def list_remediations_endpoint(
    baseline_assessment_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> list[RemediationWorkflowOut]:
    return list_remediations(db, baseline_assessment_id=baseline_assessment_id)


@router.get(
    "/remediations/{remediation_id}",
    response_model=RemediationWorkflowOut,
)
def get_remediation_endpoint(
    remediation_id: UUID,
    db: Session = Depends(get_db),
) -> RemediationWorkflowOut:
    workflow = get_remediation(db, remediation_id)
    if workflow is None:
        raise HTTPException(status_code=404, detail="Remediation workflow not found")
    return workflow


@router.post(
    "/remediations/{remediation_id}/confirm",
    response_model=RemediationWorkflowOut,
)
def confirm_remediation_endpoint(
    remediation_id: UUID,
    request: RemediationConfirmRequest,
    db: Session = Depends(get_db),
) -> RemediationWorkflowOut:
    try:
        return confirm_remediation(db, remediation_id, request)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/remediations/{remediation_id}/verify",
    response_model=RemediationWorkflowOut,
)
def verify_remediation_endpoint(
    remediation_id: UUID,
    request: RemediationVerifyRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RemediationWorkflowOut:
    try:
        return verify_remediation(db, settings, remediation_id, request)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/remediations/{remediation_id}/comparison",
    response_model=RemediationComparisonOut,
)
def get_remediation_comparison_endpoint(
    remediation_id: UUID,
    db: Session = Depends(get_db),
) -> RemediationComparisonOut:
    try:
        return get_remediation_comparison(db, remediation_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
