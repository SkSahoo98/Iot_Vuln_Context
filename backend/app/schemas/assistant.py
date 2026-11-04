"""Schemas for the controlled assistant explanation endpoint."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ExplainIntent = Literal["EXPLAIN", "FIX", "SUMMARY"]
ExplainSubject = Literal["RISK", "ISSUES"]

ExplainStatus = Literal[
    "COMPLETE",
    "NEEDS_ASSESSMENT",
    "ASSESSMENT_INCOMPLETE",
    "ASSESSMENT_FAILED",
    "ASSESSMENT_RUNNING",
    "OUT_OF_SCOPE",
    "ISSUE_NOT_FOUND",
    "ERROR",
]

CHECK_ID_PATTERN = r"^[A-Z][A-Z0-9]{1,15}(?:-[A-Z0-9]{1,15}){1,3}$"
ExplainSource = Literal["AI", "DETERMINISTIC_FALLBACK", "DETERMINISTIC"]
# Which recorded sections the explanation context contained (names only).
ExplainBasis = Literal[
    "RISK_RESULT",
    "RISK_CONTRIBUTORS",
    "FINDINGS",
    "REMEDIATION",
    "LIMITATIONS",
]


class AssistantExplainRequest(BaseModel):
    """
    Which explanation is wanted, nothing else. Security data (scores, levels,
    findings, evidence, remediation, status) is never accepted from the client.
    """

    model_config = ConfigDict(extra="forbid")

    intent: ExplainIntent
    subject: ExplainSubject | None = None
    # Catalog check ID of one recorded issue to focus on (e.g. "IOT-MQTT-01").
    # It only selects among the backend's own findings; it carries no data.
    issue: str | None = Field(default=None, pattern=CHECK_ID_PATTERN)

    @model_validator(mode="after")
    def _subject_matches_intent(self) -> AssistantExplainRequest:
        if self.intent == "EXPLAIN" and self.subject is None:
            raise ValueError("EXPLAIN requires subject RISK or ISSUES")
        if self.intent != "EXPLAIN" and self.subject is not None:
            raise ValueError(f"{self.intent} does not take a subject")
        if self.issue is not None and not (
            self.intent == "FIX" or (self.intent == "EXPLAIN" and self.subject == "ISSUES")
        ):
            raise ValueError("issue applies only to EXPLAIN/ISSUES and FIX")
        return self


class AssistantExplainResponse(BaseModel):
    status: ExplainStatus
    answer: str | None = None
    message: str | None = None
    source: ExplainSource | None = None
    basis: list[ExplainBasis] | None = None
