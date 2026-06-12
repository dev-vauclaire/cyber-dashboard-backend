"""Modele SQLAlchemy de la table scheduler_state."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .source import Source


class SchedulerState(Base):
    """Represente l'etat courant du scheduler par source."""

    __tablename__ = "scheduler_state"
    __table_args__ = (
        CheckConstraint(
            "last_inventory_status IN ('not_run', 'success', 'failed')",
            name="scheduler_state_last_inventory_status_check",
        ),
        CheckConstraint(
            "last_collection_status IN ('not_run', 'success', 'failed')",
            name="scheduler_state_last_collection_status_check",
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"),
        primary_key=True,
    )
    last_inventory_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_poll_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_inventory_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default=text("'not_run'"),
    )
    last_inventory_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_inventory_error_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_inventory_error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    last_collection_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default=text("'not_run'"),
    )
    last_collection_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_collection_error_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_collection_error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    source: Mapped["Source"] = relationship(back_populates="scheduler_state")
