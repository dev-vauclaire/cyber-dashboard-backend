"""Base commune des validateurs CTI."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cyber_dashboard_api.integrations.common import IntegrationRequestError, ValidationResult
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext


class BaseCtiValidator(ABC):
    """Contrat minimal des validateurs CTI."""

    provider_label = "CTI provider"

    @abstractmethod
    def validate(self, context: CtiValidationContext) -> ValidationResult:
        """Valide une configuration CTI."""

    def _map_request_error(self, error: IntegrationRequestError) -> ValidationResult:
        if error.kind == "auth_rejected":
            return ValidationResult.fail(
                f"{self.provider_label} API key was rejected",
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
