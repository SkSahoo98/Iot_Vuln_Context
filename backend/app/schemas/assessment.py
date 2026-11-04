"""Pydantic schemas for evidence-driven assessment endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

AssessmentStatus = Literal["RUNNING", "COMPLETE", "INCOMPLETE", "FAILED"]


class AssessmentCreate(BaseModel):
    target: str | None = Field(default=None, max_length=255)
    scope: Literal["AUTHORIZED_IOT", "SINGLE_DEVICE"] | None = None
    device_ids: list[str] | None = None


class AssessmentEvidenceOut(BaseModel):
    id: UUID
    assessment_id: UUID
    target: str
    port: int | None
    check_type: str
    result: str
    evidence_source: str
    observation: dict[str, Any]
    observed_at: datetime


class AssessmentFindingOut(BaseModel):
    id: UUID
    assessment_id: UUID
    finding_id: str
    finding_type: str
    category: str
    title: str
    severity: str
    confidence: float | None
    description: str | None
    target: str
    port: int | None
    evidence_reference: UUID | None
    remediation: str | None
    status: str
    created_at: datetime


class RiskSnapshotOut(BaseModel):
    id: UUID
    assessment_id: UUID
    finding_ref: UUID | None
    score: float
    risk_level: str
    score_version: str
    base_severity: str | None
    context_score: float | None
    factor_contributions: dict[str, Any]
    context_inputs: dict[str, Any]
    created_at: datetime


class AssessmentSummaryOut(BaseModel):
    id: UUID
    target: str
    assessment_type: str
    status: AssessmentStatus
    started_at: datetime
    completed_at: datetime | None
    error_summary: str | None
    metadata: dict[str, Any]
    created_at: datetime
    evidence_count: int = 0
    finding_count: int = 0
    highest_risk: float | None = None
    highest_risk_level: str | None = None


class RiskTraceFactorOut(BaseModel):
    """Recorded findings/evidence that set one IoT-RISK-v1 context factor."""

    factor: str
    rule: Literal["FINDING_TYPE", "OPEN_PORT_EVIDENCE", "CONFIGURATION"]
    finding_refs: list[UUID] = Field(default_factory=list)
    evidence_refs: list[UUID] = Field(default_factory=list)


class RiskTraceOut(BaseModel):
    """Derived on read from recorded rows; contains no scores."""

    score_version: str
    overall_rule: Literal["HIGHEST_FINDING_RISK"]
    overall_finding_refs: list[UUID] = Field(default_factory=list)
    factors: list[RiskTraceFactorOut] = Field(default_factory=list)


class AssessmentDetailOut(AssessmentSummaryOut):
    evidence: list[AssessmentEvidenceOut] = Field(default_factory=list)
    findings: list[AssessmentFindingOut] = Field(default_factory=list)
    risk_snapshots: list[RiskSnapshotOut] = Field(default_factory=list)
    risk_trace: RiskTraceOut | None = None
