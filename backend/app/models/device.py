"""Device inventory models."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import INET, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDPrimaryKeyMixin, TimestampUpdateMixin

DEVICE_CRITICALITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class Device(UUIDPrimaryKeyMixin, TimestampUpdateMixin, Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(
            f"criticality IN {DEVICE_CRITICALITIES}",
            name="ck_devices_criticality",
        ),
        Index("idx_devices_ip_address", "ip_address"),
        Index("idx_devices_mac_address", "mac_address"),
        Index("idx_devices_device_type", "device_type"),
        Index("idx_devices_criticality", "criticality"),
        Index("idx_devices_is_active", "is_active"),
        Index(
            "uq_devices_device_name_active",
            "device_name",
            unique=True,
            postgresql_where="is_active = true",
        ),
    )

    device_name: Mapped[str] = mapped_column(String(128), nullable=False)
    device_type: Mapped[str] = mapped_column(String(50), nullable=False)
    manufacturer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    network_zone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    interfaces: Mapped[list["DeviceInterface"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
    )
    scan_sessions: Mapped[list["ScanSession"]] = relationship(back_populates="device")
    findings: Mapped[list["Finding"]] = relationship(back_populates="device")
    risk_scores: Mapped[list["RiskScore"]] = relationship(back_populates="device")
    risk_history: Mapped[list["RiskHistory"]] = relationship(back_populates="device")
    ml_predictions: Mapped[list["MLPrediction"]] = relationship(back_populates="device")
    ai_explanations: Mapped[list["AIExplanation"]] = relationship(back_populates="device")  # noqa: F821


class DeviceInterface(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "device_interfaces"
    __table_args__ = (
        Index("idx_device_interfaces_device_id", "device_id"),
        Index("idx_device_interfaces_mac_address", "mac_address"),
        Index("idx_device_interfaces_ipv4", "ipv4"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    interface_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    interface_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    ipv4: Mapped[str | None] = mapped_column(INET, nullable=True)
    ipv6: Mapped[str | None] = mapped_column(INET, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    device: Mapped[Device] = relationship(back_populates="interfaces")
