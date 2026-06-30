"""Schemas de reponse pour les alertes IP communes."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator

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
    sensor_type_code: str | None = None
    collector_type: str | None = None
    domain_name: str | None = None
    external_id: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    hit_count: int


class AlertEmailRequestSchema(ApiSchema):
    """Payload d'envoi manuel d'un email d'alerte."""

    recipient: str = Field(..., min_length=1, max_length=255)
    subject: str = Field(..., min_length=1, max_length=255)
    body: str = Field(..., min_length=1, max_length=10000)


class AlertEmailResponseSchema(ApiSchema):
    """Resultat public de l'envoi manuel d'un email d'alerte."""

    alert_id: int
    recipient: str
    sent: bool


class AlertDetailResponseSchema(ApiSchema):
    """Reponse detaillee pour une alerte IP commune."""

    attacker_ip: str
    sources: list[AlertDetailItemSchema]

    @field_validator("attacker_ip", mode="before")
    @classmethod
    def strip_attacker_ip_prefix(cls, value: object) -> str:
        """Retire le suffixe CIDR des adresses IP exposees."""
        return strip_ip_prefix(value)
