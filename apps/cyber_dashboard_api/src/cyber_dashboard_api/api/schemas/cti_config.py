"""Schemas API pour les configurations CTI."""

from __future__ import annotations

from datetime import datetime

from .common import ApiSchema


class CtiConfigSchema(ApiSchema):
    """Representation publique d'une configuration CTI."""

    id: int
    code: str
    label: str
    is_key_required: bool
    is_active: bool
    has_api_key: bool
    api_key_hint: str | None
    last_validation_status: str | None
    last_validation_at: datetime | None
    last_validation_error: str | None
    created_at: datetime
    updated_at: datetime


class CtiConfigListResponseSchema(ApiSchema):
    """Liste des configurations CTI."""

    items: list[CtiConfigSchema]


class CtiConfigUpdateRequestSchema(ApiSchema):
    """Payload de mise a jour d'une configuration CTI."""

    label: str | None = None
    api_key: str | None = None
