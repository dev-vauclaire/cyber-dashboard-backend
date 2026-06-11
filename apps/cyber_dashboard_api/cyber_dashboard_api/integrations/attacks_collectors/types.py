"""Types de validation des collecteurs d'attaques."""

from __future__ import annotations

from dataclasses import dataclass

from cyber_dashboard_api.integrations.common import ValidationResult


@dataclass(frozen=True, slots=True)
class AttacksCollectorValidationContext:
    """Contexte transmis aux validateurs de collecteurs."""

    collector_type: str
    api_key: str | None
    email: str | None


__all__ = ["AttacksCollectorValidationContext", "ValidationResult"]
