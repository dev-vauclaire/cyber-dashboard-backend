"""Modele SQLAlchemy de la table attacks."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .enums import CorrelationStatus
from .sqlalchemy_enums import status_correlation_enum

if TYPE_CHECKING:
    from .source import Source


class Attack(Base):
    """Represente une attaque collectee."""

    __tablename__ = "attacks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    deduplication_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
    )
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(150), nullable=True)
    attacker_ip: Mapped[str] = mapped_column(INET, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )
    attack_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    raw_payload: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    correlation_status: Mapped[CorrelationStatus] = mapped_column(
        status_correlation_enum,
        nullable=False,
        server_default=text("'pending'"),
    )

    source: Mapped["Source"] = relationship(back_populates="attacks")
