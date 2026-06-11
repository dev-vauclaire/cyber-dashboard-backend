"""Schemas de reponse pour les alertes IP communes."""

from __future__ import annotations

from datetime import datetime

from pydantic import field_validator

from .common import ApiSchema, PaginationSchema, strip_ip_prefix


class AlertListItemSchema(ApiSchema):
    """Representation resumee d'une alerte IP commune."""

    id: int
    attacker_ip: str
    distinct_source_count: int
    first_seen_at: datetime
    last_seen_at: datetime

    @field_validator("attacker_ip", mode="before")
    @classmethod
    def strip_attacker_ip_prefix(cls, value: object) -> str:
        """Retire le suffixe CIDR des adresses IP exposees."""
        return strip_ip_prefix(value)


class AlertListResponseSchema(ApiSchema):
    """Liste paginee des alertes IP communes."""

    pagination: PaginationSchema
    items: list[AlertListItemSchema]


class AlertDetailItemSchema(ApiSchema):
    """Detail d'une alerte pour une source associee."""

    source_id: int
    source_name: str
    first_seen_at: datetime
    last_seen_at: datetime
    hit_count: int


class AlertDetailResponseSchema(ApiSchema):
    """Reponse detaillee pour une alerte IP commune."""

    attacker_ip: str
    sources: list[AlertDetailItemSchema]

    @field_validator("attacker_ip", mode="before")
    @classmethod
    def strip_attacker_ip_prefix(cls, value: object) -> str:
        """Retire le suffixe CIDR des adresses IP exposees."""
        return strip_ip_prefix(value)
