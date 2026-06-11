"""Modele SQLAlchemy de la table smtp_config."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, SmallInteger, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class SmtpConfig(Base):
    """Configuration SMTP singleton."""

    __tablename__ = "smtp_config"
    __table_args__ = (
        CheckConstraint("id = 1", name="smtp_config_singleton"),
        CheckConstraint(
            "smtp_port IS NULL OR smtp_port BETWEEN 1 AND 65535",
            name="smtp_config_port_range",
        ),
        CheckConstraint(
            "last_validation_status IS NULL "
            "OR last_validation_status IN ('success', 'failed', 'not_tested')",
            name="smtp_config_validation_status_check",
        ),
    )

    id: Mapped[int] = mapped_column(
        SmallInteger,
        primary_key=True,
        server_default=text("1"),
    )
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_port: Mapped[int | None] = mapped_column(nullable=True)
    smtp_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_smtp_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    smtp_password_hint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    smtp_from: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_from_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(
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
