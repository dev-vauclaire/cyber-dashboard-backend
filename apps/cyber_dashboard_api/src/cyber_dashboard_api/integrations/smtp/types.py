"""Types de validation SMTP."""

from __future__ import annotations

from dataclasses import dataclass

from cyber_dashboard_api.integrations.common import ValidationResult


@dataclass(frozen=True, slots=True)
class SmtpValidationContext:
    """Contexte transmis au validateur SMTP."""

    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    timeout_seconds: float


__all__ = ["SmtpValidationContext", "ValidationResult"]
