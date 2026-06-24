"""Schemas de reponse et de filtres pour les attaques."""

from __future__ import annotations

from datetime import datetime

from pydantic import ConfigDict, Field, field_validator

from .common import ApiSchema, PaginationSchema, strip_ip_prefix


class AttackListQuerySchema(ApiSchema):
    """Filtres simples de la liste paginee des attaques."""

    model_config = ConfigDict(populate_by_name=True)

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    sensor_type: str | None = None
    source_id: int | None = Field(default=None, ge=1)
    attack_type: str | None = None
    from_at: datetime | None = Field(default=None, alias="from")
    to_at: datetime | None = Field(default=None, alias="to")


class AttackItemSchema(ApiSchema):
    """Representation d'une attaque dans la liste paginee."""

    id: int
    source_id: int
    source_name: str
    sensor_type_code: str
    attacker_ip: str
    occurred_at: datetime
    collected_at: datetime
    attack_type: str | None = None

    @field_validator("attacker_ip", mode="before")
    @classmethod
    def strip_attacker_ip_prefix(cls, value: object) -> str:
        """Retire le suffixe CIDR des adresses IP exposees."""
        return strip_ip_prefix(value)


class AttackListResponseSchema(ApiSchema):
    """Reponse paginee de la liste des attaques."""

    pagination: PaginationSchema
    items: list[AttackItemSchema]
