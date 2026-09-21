"""Shared Pydantic response schemas for the API."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DeviceTelemetryOut(BaseModel):
    temperature: float
    humidity: float
    timestamp: datetime


class DeviceOut(BaseModel):
    id: int
    device_id: str
    ip_address: str | None = None
    mac_address: str | None = None
    device_type: str
    firmware_version: str | None = None
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
    latest_telemetry: DeviceTelemetryOut | None = None


class FindingOut(BaseModel):
    finding_type: str
    title: str
    severity: str
    confidence: float
    description: str
    impact: str
    recommendation: str
    evidence: dict[str, Any]


class RiskItemOut(BaseModel):
    finding_type: str
    base_severity: str
    score: float
    risk_level: str
    score_version: str
    calculation_method: str
    base_severity_contribution: float
    context_score: float
    factors: dict[str, float]
    factor_contributions: dict[str, dict[str, float]]
    evidence: dict[str, Any]


class RiskSummaryOut(BaseModel):
    score_version: str
    mqtt_broker_host: str
    mqtt_broker_port: int
    findings_assessed: int
    highest_score: float | None
    highest_level: str | None
    items: list[RiskItemOut]


class ExperimentResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    metric_name: str
    metric_value: Decimal | None
    model_name: str | None
    notes: str | None
    created_at: datetime


class ExperimentSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    experiment_name: str
    model_version: str | None
    status: str | None
    created_at: datetime
    conclusion: str | None = None


class ExperimentDetailOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    experiment_name: str
    objective: str | None
    hypothesis: str | None
    methodology: str | None
    dataset_version: str | None
    model_version: str | None
    parameters: dict[str, Any] | None
    start_date: datetime | None
    end_date: datetime | None
    status: str | None
    conclusion: str | None
    created_at: datetime
    results: list[ExperimentResultOut] = Field(default_factory=list)


class AIExplanationOut(BaseModel):
    finding_id: str
    summary: str
    evidence: list[str]
    why_it_matters: str
    iot_context: str
    risk_explanation: str
    potential_impact: str
    attack_scenario: str
    remediation: list[str]
    # Optional metadata for dashboard source labeling (backward compatible).
    source: str | None = None  # "ollama" | "fallback"
    model: str | None = None
    generated_at: datetime | None = None
