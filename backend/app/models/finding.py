"""Finding, vulnerability, and CVE models."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, TimestampUpdateMixin, UUIDPrimaryKeyMixin

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
FINDING_STATUSES = ("OPEN", "CONFIRMED", "MITIGATED", "ACCEPTED", "FALSE_POSITIVE")

finding_cves = Table(
    "finding_cves",
    Base.metadata,
    Column(
        "finding_id",
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "cve_id",
        UUID(as_uuid=True),
        ForeignKey("cves.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
)


class Vulnerability(UUIDPrimaryKeyMixin, TimestampUpdateMixin, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(
            f"severity IS NULL OR severity IN {SEVERITIES}",
            name="ck_vulnerabilities_severity",
        ),
    )

    vulnerability_code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(back_populates="vulnerability")


class Cve(UUIDPrimaryKeyMixin, TimestampUpdateMixin, Base):
    __tablename__ = "cves"
    __table_args__ = (
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_cves_cvss_score",
        ),
        CheckConstraint(
            f"severity IS NULL OR severity IN {SEVERITIES}",
            name="ck_cves_severity",
        ),
        Index("idx_cves_cve_id", "cve_id"),
    )

    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    references: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        secondary=finding_cves,
        back_populates="cves",
    )


class Finding(UUIDPrimaryKeyMixin, TimestampUpdateMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(f"severity IN {SEVERITIES}", name="ck_findings_severity"),
        CheckConstraint(f"status IN {FINDING_STATUSES}", name="ck_findings_status"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_findings_confidence",
        ),
        Index("idx_findings_device_id", "device_id"),
        Index("idx_findings_scan_session_id", "scan_session_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_status", "status"),
        Index("idx_findings_vulnerability_id", "vulnerability_id"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scan_session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_sessions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scan_service_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_services.id", ondelete="SET NULL"),
        nullable=True,
    )
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    finding_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    device: Mapped["Device"] = relationship(back_populates="findings")
    scan_session: Mapped["ScanSession"] = relationship(back_populates="findings")
    scan_service: Mapped["ScanService | None"] = relationship(back_populates="findings")
    vulnerability: Mapped[Vulnerability | None] = relationship(back_populates="findings")
    cves: Mapped[list[Cve]] = relationship(
        secondary=finding_cves,
        back_populates="findings",
    )
    remediation_actions: Mapped[list["RemediationAction"]] = relationship(
        secondary="finding_remediations",
        back_populates="findings",
    )
    risk_factor_values: Mapped[list["RiskFactorValue"]] = relationship(
        back_populates="finding",
    )
