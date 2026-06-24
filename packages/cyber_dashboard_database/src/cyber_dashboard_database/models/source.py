"""Modele SQLAlchemy de la table sources."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .attack import Attack
    from .attacks_collector_config import AttacksCollectorConfig
    from .common_ip_alert_source import CommonIpAlertSource
    from .ogo_source import OgoSource
    from .scheduler_state import SchedulerState
    from .serenicity_source import SerenicitySource
    from .sensor_type import SensorType


class Source(Base):
    """Represente une source de collecte."""

    __tablename__ = "sources"
    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(name)) > 0",
            name="sources_name_not_empty",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    sensor_type_id: Mapped[int] = mapped_column(
        ForeignKey("sensor_types.id"),
        nullable=False,
    )
    attacks_collector_config_id: Mapped[int | None] = mapped_column(
        ForeignKey("attacks_collector_config.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        nullable=False,
        server_default=text("TRUE"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )
    color: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    sensor_type: Mapped["SensorType"] = relationship(back_populates="sources")
    attacks_collector_config: Mapped["AttacksCollectorConfig | None"] = relationship(
        back_populates="sources"
    )
    attacks: Mapped[list["Attack"]] = relationship(back_populates="source")
    alert_sources: Mapped[list["CommonIpAlertSource"]] = relationship(
        back_populates="source"
    )
    ogo_source: Mapped["OgoSource | None"] = relationship(
        back_populates="source",
        uselist=False,
        cascade="all, delete-orphan",
    )
    serenicity_source: Mapped["SerenicitySource | None"] = relationship(
        back_populates="source",
        uselist=False,
        cascade="all, delete-orphan",
    )
    scheduler_state: Mapped["SchedulerState | None"] = relationship(
        back_populates="source",
        uselist=False,
    )
