"""Schemas techniques simples de l'API."""

from __future__ import annotations

from .common import ApiSchema


class HealthcheckSchema(ApiSchema):
    """Reponse minimale de disponibilite de l'API."""

    status: str
