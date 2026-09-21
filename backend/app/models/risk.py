"""Risk scoring and explainability factor models."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, TimestampUpdateMixin, UUIDPrimaryKeyMixin

RISK_LEVELS = ("LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL")


class RiskLevelThreshold(UUIDPrimaryKeyMixin, Base):
    """Configurable risk bands per score_version — not hard-coded in application logic."""

    __tablename__ = "risk_level_thresholds"
    __table_args__ = (
        CheckConstraint("min_score >= 0 AND max_score <= 100", name="ck_risk_level_thresholds_range"),
        CheckConstraint("min_score <= max_score", name="ck_risk_level_thresholds_order"),
        UniqueConstraint("score_version", "level_name", name="uq_risk_level_thresholds_version_level"),
    )

    score_version: Mapped[str] = mapped_column(String(32), nullable=False)
    level_name: Mapped[str] = mapped_column(String(20), nullable=False)
    min_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    max_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class RiskScore(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "risk_scores"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_scores_score"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_risk_scores_confidence",
        ),
        Index("idx_risk_scores_device_id", "device_id"),
        Index("idx_risk_scores_calculated_at", "calculated_at"),
        Index("idx_risk_scores_device_calculated", "device_id", "calculated_at"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scan_session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    score_version: Mapped[str] = mapped_column(String(32), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    calculation_method: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    device: Mapped["Device"] = relationship(back_populates="risk_scores")
    scan_session: Mapped["ScanSession | None"] = relationship(back_populates="risk_scores")
    factor_values: Mapped[list["RiskFactorValue"]] = relationship(
        back_populates="risk_score",
        cascade="all, delete-orphan",
    )
    risk_history: Mapped[list["RiskHistory"]] = relationship(back_populates="risk_score")
    ai_explanations: Mapped[list["AIExplanation"]] = relationship(back_populates="risk_score")
    ml_predictions: Mapped[list["MLPrediction"]] = relationship(back_populates="risk_score")


class RiskFactor(UUIDPrimaryKeyMixin, TimestampUpdateMixin, Base):
    __tablename__ = "risk_factors"

    factor_code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    factor_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    default_weight: Mapped[Decimal] = mapped_column(Numeric(6, 3), nullable=False)
    max_contribution: Mapped[Decimal] = mapped_column(Numeric(6, 3), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    factor_values: Mapped[list["RiskFactorValue"]] = relationship(back_populates="risk_factor")


class RiskFactorValue(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "risk_factor_values"
    __table_args__ = (
        UniqueConstraint("risk_score_id", "risk_factor_id", name="uq_risk_factor_values_score_factor"),
        Index("idx_risk_factor_values_risk_score_id", "risk_score_id"),
    )

    risk_score_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("risk_scores.id", ondelete="CASCADE"),
        nullable=False,
    )
    risk_factor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("risk_factors.id", ondelete="RESTRICT"),
        nullable=False,
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
    )
    raw_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_value: Mapped[Decimal | None] = mapped_column(Numeric(5, 4), nullable=True)
    weight: Mapped[Decimal] = mapped_column(Numeric(6, 3), nullable=False)
    contribution: Mapped[Decimal] = mapped_column(Numeric(6, 3), nullable=False)
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    risk_score: Mapped[RiskScore] = relationship(back_populates="factor_values")
    risk_factor: Mapped[RiskFactor] = relationship(back_populates="factor_values")
    finding: Mapped["Finding | None"] = relationship(back_populates="risk_factor_values")


class RiskHistory(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "risk_history"
    __table_args__ = (Index("idx_risk_history_device_id", "device_id", "changed_at"),)

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
    )
    risk_score_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("risk_scores.id", ondelete="RESTRICT"),
        nullable=False,
    )
    previous_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2), nullable=True)
    new_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    previous_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    new_level: Mapped[str] = mapped_column(String(20), nullable=False)
    change_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    device: Mapped["Device"] = relationship(back_populates="risk_history")
    risk_score: Mapped[RiskScore] = relationship(back_populates="risk_history")
