"""Base declarative partagee pour les modeles SQLAlchemy."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base commune des modeles SQLAlchemy."""

