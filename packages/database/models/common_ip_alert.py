"""Modele SQLAlchemy de la table common_ip_alerts."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, Integer, String, text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .common_ip_alert_source import CommonIpAlertSource


class CommonIpAlert(Base):
    """Represente une alerte globale sur une IP commune."""

    __tablename__ = "common_ip_alerts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    attacker_ip: Mapped[str] = mapped_column(INET, nullable=False, unique=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    distinct_source_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("2"),
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=text("'open'"),
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

    alert_sources: Mapped[list["CommonIpAlertSource"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
    )

