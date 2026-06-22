"""Schemas API pour la configuration SMTP."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from .common import ApiSchema


class SmtpConfigSchema(ApiSchema):
    """Representation publique de la configuration SMTP."""

    id: int
    smtp_host: str | None
    smtp_port: int | None
    smtp_user: str | None
    smtp_from: str | None
    smtp_from_name: str | None
    is_active: bool
    has_smtp_password: bool
    smtp_password_hint: str | None
    last_validation_status: str | None
    last_validation_at: datetime | None
    last_validation_error: str | None
    created_at: datetime
    updated_at: datetime


class SmtpConfigUpdateRequestSchema(ApiSchema):
    """Payload de mise a jour partielle de la configuration SMTP."""

    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_user: str | None = Field(default=None, max_length=255)
    smtp_password: str | None = Field(default=None, max_length=4096)
    smtp_from: str | None = Field(default=None, max_length=255)
    smtp_from_name: str | None = Field(default=None, max_length=255)


class SmtpEmailRequestSchema(ApiSchema):
    """Payload d'envoi d'un email via la configuration SMTP active."""

    recipient: str = Field(..., min_length=1, max_length=255)
    subject: str = Field(..., min_length=1, max_length=255)
    body: str = Field(..., min_length=1, max_length=10000)


class SmtpEmailResponseSchema(ApiSchema):
    """Resultat public de l'envoi d'un email SMTP."""

    recipient: str
    sent: bool
