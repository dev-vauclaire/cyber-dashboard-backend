"""Modele SQLAlchemy de la table serenicity_sources."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, Float, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .source import Source


class SerenicitySource(Base):
    """Source specialisee pour Serenicity."""

    __tablename__ = "serenicity_sources"
    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(external_id)) > 0",
            name="serenicity_sources_external_id_not_empty",
        ),
        CheckConstraint(
            "latitude IS NULL OR latitude BETWEEN -90 AND 90",
            name="serenicity_sources_latitude_range",
        ),
        CheckConstraint(
            "longitude IS NULL OR longitude BETWEEN -180 AND 180",
            name="serenicity_sources_longitude_range",
        ),
        UniqueConstraint(
            "external_id",
            name="serenicity_sources_external_id_unique",
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"),
        primary_key=True,
    )
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)

    source: Mapped["Source"] = relationship(back_populates="serenicity_source")
