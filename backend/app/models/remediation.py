"""Remediation action models."""

import uuid

from sqlalchemy import Column, ForeignKey, String, Table, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampUpdateMixin, UUIDPrimaryKeyMixin

finding_remediations = Table(
    "finding_remediations",
    Base.metadata,
    Column(
        "finding_id",
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "remediation_action_id",
        UUID(as_uuid=True),
        ForeignKey("remediation_actions.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
)


class RemediationAction(UUIDPrimaryKeyMixin, TimestampUpdateMixin, Base):
    __tablename__ = "remediation_actions"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    priority: Mapped[str | None] = mapped_column(String(20), nullable=True)
    estimated_effort: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verification_method: Mapped[str | None] = mapped_column(Text, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        secondary=finding_remediations,
        back_populates="remediation_actions",
    )
