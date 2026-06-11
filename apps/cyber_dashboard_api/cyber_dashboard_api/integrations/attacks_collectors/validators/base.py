"""Base commune des validateurs de collecteurs."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cyber_dashboard_api.integrations.attacks_collectors.types import (
    AttacksCollectorValidationContext,
)
from cyber_dashboard_api.integrations.common import IntegrationRequestError, ValidationResult


class BaseAttacksCollectorValidator(ABC):
    """Contrat minimal des validateurs de collecteurs."""

    provider_label = "Attacks collector"

    @abstractmethod
    def validate(
        self,
        context: AttacksCollectorValidationContext,
    ) -> ValidationResult:
        """Valide une configuration de collecteur."""

    def _map_request_error(self, error: IntegrationRequestError) -> ValidationResult:
        if error.kind == "auth_rejected":
            return ValidationResult.fail(
                f"{self.provider_label} credentials were rejected",
                provider_status_code=error.status_code,
            )
        if error.kind == "timeout":
            return ValidationResult.fail(
                f"{self.provider_label} request timed out",
                provider_status_code=error.status_code,
            )
        if error.kind == "rate_limit":
            return ValidationResult.fail(
                f"{self.provider_label} rate limit was reached",
                provider_status_code=error.status_code,
            )
        if error.kind == "service_unavailable":
            return ValidationResult.fail(
                f"{self.provider_label} service is unavailable",
                provider_status_code=error.status_code,
            )
        if error.kind == "dns_error":
            return ValidationResult.fail(
                f"{self.provider_label} DNS resolution failed",
                provider_status_code=error.status_code,
            )
        return ValidationResult.fail(
            f"{self.provider_label} returned an unexpected response",
            provider_status_code=error.status_code,
        )
