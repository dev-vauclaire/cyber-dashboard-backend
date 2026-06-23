"""Modele SQLAlchemy de la table cti_config."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class CtiConfig(Base):
    """Configuration d'un provider CTI."""

    __tablename__ = "cti_config"
    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(code)) > 0",
            name="cti_config_code_not_empty",
        ),
        CheckConstraint(
            "LENGTH(TRIM(label)) > 0",
            name="cti_config_label_not_empty",
        ),
        CheckConstraint(
            "last_validation_status IS NULL "
            "OR last_validation_status IN ('success', 'failed', 'not_tested')",
            name="cti_config_validation_status_check",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(150), nullable=False)
    encrypted_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key_hint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_key_required: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        server_default=text("true"),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("FALSE"),
    )
    last_validation_status: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )
    last_validation_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_validation_error: Mapped[str | None] = mapped_column(Text, nullable=True)
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
