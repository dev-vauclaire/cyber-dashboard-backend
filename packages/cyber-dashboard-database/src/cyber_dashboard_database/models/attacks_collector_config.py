"""Modele SQLAlchemy de la table attacks_collector_config."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .enums import AttacksCollectorType
from .sqlalchemy_enums import attacks_collector_type_enum

if TYPE_CHECKING:
    from .source import Source


class AttacksCollectorConfig(Base):
    """Configuration d'un collecteur d'attaques."""

    __tablename__ = "attacks_collector_config"
    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(name)) > 0",
            name="attacks_collector_config_name_not_empty",
        ),
        UniqueConstraint(
            "collector_type",
            "name",
            name="attacks_collector_config_unique_name_per_type",
        ),
        CheckConstraint(
            "last_validation_status IS NULL "
            "OR last_validation_status IN ('success', 'failed', 'not_tested')",
            name="attacks_collector_config_validation_status_check",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(30), nullable=False)
    collector_type: Mapped[AttacksCollectorType] = mapped_column(
        attacks_collector_type_enum,
        nullable=False,
    )
    encrypted_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email_hint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    encrypted_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key_hint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        nullable=False,
        server_default=text("FALSE"),
    )
    inventory_requested: Mapped[bool] = mapped_column(
        nullable=False,
        server_default=text("TRUE"),
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

    sources: Mapped[list["Source"]] = relationship(
        back_populates="attacks_collector_config"
    )
