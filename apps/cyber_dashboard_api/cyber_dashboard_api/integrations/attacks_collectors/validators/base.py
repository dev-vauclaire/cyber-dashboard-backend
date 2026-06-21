"""Base commune des validateurs de collecteurs."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cyber_dashboard_api.integrations.attacks_collectors.types import (
    AttacksCollectorValidationContext,
)
from cyber_dashboard_api.integrations.common import IntegrationRequestError, ValidationResult


class BaseAttacksCollectorValidator(ABC):
    """Contrat minimal des validateurs de collecteurs."""

    provider_label = "collecteur d'attaques"

    @abstractmethod
    def validate(
        self,
        context: AttacksCollectorValidationContext,
    ) -> ValidationResult:
        """Valide une configuration de collecteur."""

    def _map_request_error(self, error: IntegrationRequestError) -> ValidationResult:
        if error.kind == "auth_rejected":
            return ValidationResult.fail(
                f"Les identifiants du {self.provider_label} ont été rejetés",
                provider_status_code=error.status_code,
            )
        if error.kind == "timeout":
            return ValidationResult.fail(
                f"La requête vers le {self.provider_label} a expiré",
                provider_status_code=error.status_code,
            )
        if error.kind == "rate_limit":
            return ValidationResult.fail(
                f"La limite de débit du {self.provider_label} a été atteinte",
                provider_status_code=error.status_code,
            )
        if error.kind == "service_unavailable":
            return ValidationResult.fail(
                f"Le service du {self.provider_label} est indisponible",
                provider_status_code=error.status_code,
            )
        if error.kind == "dns_error":
            return ValidationResult.fail(
                f"La résolution DNS du {self.provider_label} a échoué",
                provider_status_code=error.status_code,
            )
        return ValidationResult.fail(
            f"Le {self.provider_label} a renvoyé une réponse inattendue",
            provider_status_code=error.status_code,
        )
