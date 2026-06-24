"""Modele SQLAlchemy de la table retention_policies."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class RetentionPolicy(Base):
    """Represente une politique de retention de donnees."""

    __tablename__ = "retention_policies"
    __table_args__ = (
        CheckConstraint(
            "target_table IN ('attacks', 'common_ip_alerts')",
            name="retention_policies_target_table_check",
        ),
        CheckConstraint(
            "retention_days > 0",
            name="retention_policies_retention_days_positive",
        ),
        CheckConstraint(
            "last_deleted_count IS NULL OR last_deleted_count >= 0",
            name="retention_policies_last_deleted_count_non_negative",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_table: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        nullable=False,
        server_default=text("FALSE"),
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_deleted_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
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
