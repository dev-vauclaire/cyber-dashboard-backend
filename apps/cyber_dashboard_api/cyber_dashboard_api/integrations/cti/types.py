"""Types de validation CTI."""

from __future__ import annotations

from dataclasses import dataclass

from cyber_dashboard_api.integrations.common import ValidationResult


@dataclass(frozen=True, slots=True)
class CtiValidationContext:
    """Contexte minimal transmis à un validateur CTI."""

    code: str
    test_ip: str
    api_key: str | None = None


__all__ = ["CtiValidationContext", "ValidationResult"]
