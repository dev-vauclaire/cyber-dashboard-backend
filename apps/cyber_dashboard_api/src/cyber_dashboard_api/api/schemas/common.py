"""Schemas partages pour les endpoints de l'API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


def strip_ip_prefix(value: object) -> str:
    """Retourne l'adresse IP sans suffixe CIDR."""
    return str(value).strip().split("/", 1)[0]


class ApiSchema(BaseModel):
    """Base commune des schemas API."""

    model_config = ConfigDict(extra="forbid")


class PaginationSchema(ApiSchema):
    """Metadonnees simples de pagination."""

    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1, le=100)
    total_items: int = Field(..., ge=0)
    total_pages: int = Field(..., ge=0)


class TimeRangeQuerySchema(ApiSchema):
    """Filtres de date partages pour les endpoints statistiques."""

    start_at: datetime
    end_at: datetime
