"""Modele SQLAlchemy de la table ogo_sources."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .source import Source


class OgoSource(Base):
    """Source specialisee pour OGO."""

    __tablename__ = "ogo_sources"
    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(site_url)) > 0",
            name="ogo_sources_site_url_not_empty",
        ),
        CheckConstraint(
            "organization_code IS NULL OR LENGTH(TRIM(organization_code)) > 0",
            name="ogo_sources_organization_code_not_empty",
        ),
        UniqueConstraint(
            "site_url",
            name="ogo_sources_site_url_unique",
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"),
        primary_key=True,
    )
    site_url: Mapped[str] = mapped_column(String(500), nullable=False)
    organization_code: Mapped[str | None] = mapped_column(String(100), nullable=True)

    source: Mapped["Source"] = relationship(back_populates="ogo_source")
