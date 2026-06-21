"""Base commune des validateurs CTI."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cyber_dashboard_api.integrations.common import IntegrationRequestError, ValidationResult
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext


class BaseCtiValidator(ABC):
    """Contrat minimal des validateurs CTI."""

    provider_label = "fournisseur CTI"

    @abstractmethod
    def validate(self, context: CtiValidationContext) -> ValidationResult:
        """Valide une configuration CTI."""

    def _map_request_error(self, error: IntegrationRequestError) -> ValidationResult:
        if error.kind == "auth_rejected":
            return ValidationResult.fail(
                f"{self.provider_label} a rejeté la clé API fournie",
                provider_status_code=error.status_code,
            )
        if error.kind == "timeout":
            return ValidationResult.fail(
                f"La requête vers {self.provider_label} a expiré",
                provider_status_code=error.status_code,
            )
        if error.kind == "rate_limit":
            return ValidationResult.fail(
                f"La limite de débit de {self.provider_label} a été atteinte",
                provider_status_code=error.status_code,
            )
        if error.kind == "service_unavailable":
            return ValidationResult.fail(
                f"Le service {self.provider_label} est indisponible",
                provider_status_code=error.status_code,
            )
        if error.kind == "dns_error":
            return ValidationResult.fail(
                f"La résolution DNS de {self.provider_label} a échoué",
                provider_status_code=error.status_code,
            )
        return ValidationResult.fail(
            f"{self.provider_label} a renvoyé une réponse inattendue",
            provider_status_code=error.status_code,
        )
