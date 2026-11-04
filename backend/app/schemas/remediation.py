"""Pydantic schemas for the remediation and verification lifecycle."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


RemediationStatus = Literal[
    "OPEN",
    "GUIDANCE_VIEWED",
    "REMEDIATION_IN_PROGRESS",
    "READY_FOR_VERIFICATION",
    "VERIFICATION_PENDING",
    "VERIFIED_RESOLVED",
    "PARTIALLY_RESOLVED",
    "STILL_PRESENT",
    "VERIFICATION_FAILED",
    "INCONCLUSIVE",
]

VerificationVerdict = Literal[
    "VERIFIED_RESOLVED",
    "PARTIALLY_RESOLVED",
    "STILL_PRESENT",
    "VERIFICATION_FAILED",
    "INCONCLUSIVE",
]


class RemediationWorkflowCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_assessment_id: UUID
    baseline_finding_id: UUID


class RemediationConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notes: str | None = Field(
        default=None,
        max_length=500,
        description="Optional user notes confirming remediation was applied",
    )


class RemediationVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: Literal["AUTO", "TARGET", "ENVIRONMENT"] = Field(
        default="AUTO",
        description="Whether to run target assessment or full environment assessment",
    )
    explicit_approval: bool = Field(
        default=True,
        description="User must explicitly approve the execution of the verification check",
    )


class RemediationVerificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workflow_id: UUID
    verification_assessment_id: UUID
    verdict: str
    verdict_rationale: str | None = None
    coverage_equivalent: bool = False
    baseline_finding_present: bool = False
    evidence_references: list[str] = Field(default_factory=list)
    risk_delta: dict[str, Any] | None = None
    created_at: datetime


class RemediationWorkflowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    baseline_assessment_id: UUID
    baseline_finding_id: UUID
    finding_fingerprint: str
    target: str
    status: str
    guidance_version: str = "1.0"
    user_confirmed_at: datetime | None = None
    verification_assessment_id: UUID | None = None
    verification_verdict: str | None = None
    verdict_rationale: str | None = None
    coverage_summary: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    verifications: list[RemediationVerificationOut] = Field(default_factory=list)
    finding_details: dict[str, Any] | None = None


class RemediationComparisonOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    workflow: RemediationWorkflowOut
    baseline: dict[str, Any]
    verification: dict[str, Any] | None = None
    verdict: str
    verdict_rationale: str | None = None
    coverage_equivalent: bool
    risk_delta: dict[str, Any] | None = None

