"""Modele SQLAlchemy de la table common_ip_alert_sources."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, PrimaryKeyConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .common_ip_alert import CommonIpAlert
    from .source import Source


class CommonIpAlertSource(Base):
    """Associe une alerte commune aux sources concernees."""

    __tablename__ = "common_ip_alert_sources"
    __table_args__ = (
        PrimaryKeyConstraint("alert_id", "source_id"),
    )

    alert_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("common_ip_alerts.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    hit_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("1"),
    )

    alert: Mapped["CommonIpAlert"] = relationship(back_populates="alert_sources")
    source: Mapped["Source"] = relationship(back_populates="alert_sources")

