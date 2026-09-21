"""Scan session, port, service, and scan observation models."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

SCANNERS = ("NMAP", "SCAPY", "OPENSSL", "CUSTOM")
SCAN_STATUSES = ("PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")
PORT_PROTOCOLS = ("TCP", "UDP")
SERVICE_STATES = ("OPEN", "CLOSED", "FILTERED", "UNKNOWN")


class ScanSession(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "scan_sessions"
    __table_args__ = (
        CheckConstraint(f"scanner IN {SCANNERS}", name="ck_scan_sessions_scanner"),
        CheckConstraint(f"status IN {SCAN_STATUSES}", name="ck_scan_sessions_status"),
        Index("idx_scan_sessions_device_id", "device_id"),
        Index("idx_scan_sessions_started_at", "started_at"),
        Index("idx_scan_sessions_status", "status"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scanner: Mapped[str] = mapped_column(String(32), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    configuration: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    device: Mapped["Device"] = relationship(back_populates="scan_sessions")
    scan_services: Mapped[list["ScanService"]] = relationship(
        back_populates="scan_session",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_session")
    risk_scores: Mapped[list["RiskScore"]] = relationship(back_populates="scan_session")
    ml_predictions: Mapped[list["MLPrediction"]] = relationship(back_populates="scan_session")


class Port(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ports"
    __table_args__ = (
        CheckConstraint("port_number >= 1 AND port_number <= 65535", name="ck_ports_number"),
        CheckConstraint(f"protocol IN {PORT_PROTOCOLS}", name="ck_ports_protocol"),
        UniqueConstraint("port_number", "protocol", name="uq_ports_number_protocol"),
    )

    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(3), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan_services: Mapped[list["ScanService"]] = relationship(back_populates="port")


class Service(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Stable service type catalog (mqtt, http, telnet, etc.)."""

    __tablename__ = "services"
    __table_args__ = (
        CheckConstraint(
            "default_port IS NULL OR (default_port >= 1 AND default_port <= 65535)",
            name="ck_services_default_port",
        ),
        CheckConstraint(
            "protocol IS NULL OR protocol IN ('TCP', 'UDP')",
            name="ck_services_protocol",
        ),
    )

    service_name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    default_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(3), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan_services: Mapped[list["ScanService"]] = relationship(back_populates="service_catalog")


class ScanService(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "scan_services"
    __table_args__ = (
        CheckConstraint(f"state IN {SERVICE_STATES}", name="ck_scan_services_state"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_scan_services_confidence",
        ),
        UniqueConstraint(
            "scan_session_id",
            "port_id",
            "service_name",
            name="uq_scan_services_session_port_service",
        ),
        Index("idx_scan_services_scan_session_id", "scan_session_id"),
        Index("idx_scan_services_port_id", "port_id"),
    )

    scan_session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    port_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ports.id", ondelete="RESTRICT"),
        nullable=False,
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("services.id", ondelete="SET NULL"),
        nullable=True,
    )
    service_name: Mapped[str] = mapped_column(String(64), nullable=False)
    service_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan_session: Mapped[ScanSession] = relationship(back_populates="scan_services")
    port: Mapped[Port] = relationship(back_populates="scan_services")
    service_catalog: Mapped[Service | None] = relationship(back_populates="scan_services")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_service")
