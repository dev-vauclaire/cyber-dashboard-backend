"""Schemas API pour les collecteurs d'attaques."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from .common import ApiSchema


CollectorType = Literal["ogo", "serenicity"]


class AttacksCollectorConfigSchema(ApiSchema):
    """Representation publique d'une configuration de collecteur."""

    id: int
    name: str
    collector_type: CollectorType
    is_active: bool
    has_email: bool
    email_hint: str | None
    has_api_key: bool
    api_key_hint: str | None
    last_validation_status: str | None
    last_validation_at: datetime | None
    last_validation_error: str | None
    created_at: datetime
    updated_at: datetime


class AttacksCollectorConfigListResponseSchema(ApiSchema):
    """Liste des configurations de collecteurs."""

    items: list[AttacksCollectorConfigSchema]


class AttacksCollectorConfigCreateRequestSchema(ApiSchema):
    """Payload de creation d'une configuration de collecteur."""

    name: str
    collector_type: CollectorType
    api_key: str | None = None
    email: str | None = None
    is_active: bool = False


class AttacksCollectorConfigUpdateRequestSchema(ApiSchema):
    """Payload de mise a jour d'une configuration de collecteur."""

    name: str | None = None
    collector_type: CollectorType | None = None
    api_key: str | None = None
    email: str | None = None


class AttacksCollectorInventoryRequestSchema(ApiSchema):
    """Payload optionnel pour demander un inventaire."""

    inventory_requested_by: str | None = None


class AttacksCollectorInventoryRequestResponseSchema(ApiSchema):
    """Etat de la demande d'inventaire enregistre dans scheduler_state_v2."""

    attacks_collector_config_id: int
    inventory_requested_at: datetime
    inventory_requested_by: str
    last_inventory_status: str
    updated_at: datetime
