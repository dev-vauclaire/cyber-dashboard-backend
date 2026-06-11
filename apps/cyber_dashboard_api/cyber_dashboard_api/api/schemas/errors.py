"""Schemas de reponse pour les erreurs de l'API."""

from __future__ import annotations

from typing import Any

from .common import ApiSchema


class ErrorDetailSchema(ApiSchema):
    """Detail optionnel d'une erreur de validation."""

    location: str
    message: str
    type: str
    input: Any | None = None


class ErrorInfoSchema(ApiSchema):
    """Information principale d'une erreur API."""

    code: str
    message: str
    details: list[ErrorDetailSchema] | None = None


class ErrorResponseSchema(ApiSchema):
    """Envelope commune des erreurs API."""

    error: ErrorInfoSchema
