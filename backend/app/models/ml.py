"""ML model, prediction, and AI explanation models."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

EXPLANATION_TYPES = ("SHAP", "RULE_BASED", "LLM_ASSISTED", "HYBRID")


class MLModel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ml_models"
    __table_args__ = (
        UniqueConstraint("model_name", "version", name="uq_ml_models_name_version"),
    )

    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    features: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    metrics: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    model_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    training_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    predictions: Mapped[list["MLPrediction"]] = relationship(back_populates="ml_model")


class MLPrediction(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ml_predictions"
    __table_args__ = (
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_ml_predictions_confidence",
        ),
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
    ml_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ml_models.id", ondelete="RESTRICT"),
        nullable=False,
    )
    risk_score_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("risk_scores.id", ondelete="SET NULL"),
        nullable=True,
    )
    predicted_class: Mapped[str | None] = mapped_column(String(32), nullable=True)
    predicted_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2), nullable=True)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    features: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    prediction_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    device: Mapped["Device"] = relationship(back_populates="ml_predictions")
    scan_session: Mapped["ScanSession | None"] = relationship(back_populates="ml_predictions")
    ml_model: Mapped[MLModel] = relationship(back_populates="predictions")
    risk_score: Mapped["RiskScore | None"] = relationship(back_populates="ml_predictions")
    ai_explanations: Mapped[list["AIExplanation"]] = relationship(back_populates="ml_prediction")


class AIExplanation(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ai_explanations"
    __table_args__ = (
        CheckConstraint(
            f"explanation_type IN {EXPLANATION_TYPES}",
            name="ck_ai_explanations_type",
        ),
    )

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
    ml_prediction_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ml_predictions.id", ondelete="SET NULL"),
        nullable=True,
    )
    explanation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    top_factors: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    explanation_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    device: Mapped["Device"] = relationship(back_populates="ai_explanations")
    risk_score: Mapped["RiskScore"] = relationship(back_populates="ai_explanations")
    ml_prediction: Mapped[MLPrediction | None] = relationship(back_populates="ai_explanations")
