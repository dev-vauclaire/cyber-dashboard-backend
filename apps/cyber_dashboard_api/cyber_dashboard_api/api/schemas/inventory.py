"""Schemas de reponse pour l'inventaire des capteurs."""

from __future__ import annotations

from typing import Annotated
from datetime import datetime

from pydantic import StringConstraints, field_validator

from cyber_dashboard_api.api.validation import validate_source_name
from .common import ApiSchema


class SensorInventoryItemSchema(ApiSchema):
    """Etat agrege d'un type de capteur."""

    sensor_type_code: str
    sensor_type_label: str
    active_count: int
    inactive_count: int


class SensorInventoryResponseSchema(ApiSchema):
    """Liste des types de capteurs et de leur inventaire."""

    items: list[SensorInventoryItemSchema]


class SourceItemSchema(ApiSchema):
    """Representation simple d'une source individuelle."""

    source_id: int
    source_name: str
    domain_name: str | None
    is_active: bool
    created_at: datetime
    sensor_type_code: str
    color: str | None
    sensor_type_label: str


class SourceListResponseSchema(ApiSchema):
    """Liste simple des sources individuelles."""

    items: list[SourceItemSchema]


class SourceRenameRequestSchema(ApiSchema):
    """Payload minimal pour renommer une source."""

    source_name: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=150),
    ]

    @field_validator("source_name")
    @classmethod
    def validate_source_name_field(cls, value: str) -> str:
        """Verifie que le nom fourni reste propre et exploitable."""
        return validate_source_name(value)


class SourceStatusUpdateRequestSchema(ApiSchema):
    """Payload minimal pour changer l'etat actif d'une source."""
    is_active: bool

class SourceColorUpdateRequestSchema(ApiSchema):
    """Payload minimal pour changer la couleur d'une source."""

    color: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            pattern=r"^#[0-9A-Fa-f]{6}$",
        ),
    ]
