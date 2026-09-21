"""API v1 routers."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.schemas.api import (
    AIExplanationOut,
    DeviceOut,
    ExperimentDetailOut,
    ExperimentSummaryOut,
    FindingOut,
    RiskSummaryOut,
)
from app.services.ai_explanation import explain_finding
from app.services.device_service import list_devices
from app.services.experiment_service import get_experiment, list_experiments
from app.services.finding_service import list_findings
from app.services.risk_service import assess_risk

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
