"""Schemas API pour les politiques de retention."""

from __future__ import annotations

from datetime import datetime

from .common import ApiSchema


class RetentionPolicySchema(ApiSchema):
    """Representation publique d'une politique de retention."""

    id: int
    target_table: str
    retention_days: int
    is_active: bool
    last_run_at: datetime | None
    last_deleted_count: int | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class RetentionPolicyListResponseSchema(ApiSchema):
    """Liste des politiques de retention."""

    items: list[RetentionPolicySchema]


class RetentionPolicyUpdateRequestSchema(ApiSchema):
    """Payload de mise a jour d'une politique de retention."""

    retention_days: int | None = None
    is_active: bool | None = None
