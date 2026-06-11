"""Modele SQLAlchemy de la table sensor_types."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .source import Source


class SensorType(Base):
    """Represente un type de capteur."""

    __tablename__ = "sensor_types"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(150), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    color: Mapped[str] = mapped_column(
        String(7),
        nullable=False,
        server_default=text("'#FF0000'"),
    )

    sources: Mapped[list["Source"]] = relationship(back_populates="sensor_type")

