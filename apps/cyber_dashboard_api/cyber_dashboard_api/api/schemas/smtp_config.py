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
    auto_email_enabled: bool
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
    auto_email_enabled: bool | None = None
