"""
Evidence and finding types shared by every scanner module.

Evidence is a record of something a tool actually observed. A finding is
only ever created from an Evidence object; configuration values are never
accepted as proof of a vulnerability.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

EVIDENCE_SOURCES = frozenset(
    {
        "ACTIVE_PROBE",
        "NMAP",
        "HTTP_PROBE",
        "TLS_PROBE",
        "MQTT_PROBE",
        "DATABASE",
        "CONFIGURATION",
    }
)

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class Evidence:
    """One observation produced by an assessment tool."""

    target: str
    check_type: str
    result: str
    evidence_source: str
    observation: dict[str, Any]
    port: int | None = None
    observed_at: datetime = field(default_factory=utc_now)
    id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        if self.evidence_source not in EVIDENCE_SOURCES:
            raise ValueError(f"Unknown evidence source: {self.evidence_source}")


@dataclass
class FindingCandidate:
    """A deterministic finding backed by exactly one Evidence record."""

    finding_id: str
    finding_type: str
    category: str
    title: str
    severity: str
    confidence: float
    description: str
    remediation: str
    target: str
    evidence: Evidence
    port: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unknown severity: {self.severity}")
        if self.evidence.evidence_source == "CONFIGURATION":
            raise ValueError(
                "Configuration values cannot be used as vulnerability evidence"
            )
