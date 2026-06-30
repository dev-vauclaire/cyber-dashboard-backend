"""Modele SQLAlchemy de la table ogo_sources."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .source import Source


class OgoSource(Base):
    """Source specialisee pour OGO."""

    __tablename__ = "ogo_sources"
    __table_args__ = (
        CheckConstraint(
            "LENGTH(TRIM(domain_name)) > 0",
            name="ogo_sources_domain_name_not_empty",
        ),
        UniqueConstraint(
            "domain_name",
            name="ogo_sources_domain_name_unique",
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"),
        primary_key=True,
    )
    domain_name: Mapped[str] = mapped_column(String(500), nullable=False)
    organization_codes: Mapped[list[str]] = mapped_column(
        ARRAY(String(100)),
        nullable=False,
        default=list,
        server_default=text("'{}'::character varying[]"),
    )

    source: Mapped["Source"] = relationship(back_populates="ogo_source")
