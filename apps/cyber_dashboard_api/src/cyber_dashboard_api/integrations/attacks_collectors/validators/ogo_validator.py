"""Validateur OGO."""

from __future__ import annotations

from cyber_dashboard_api.integrations.attacks_collectors.clients.ogo_client import (
    OgoClient,
    OgoCredentialsValidationResult,
)
from cyber_dashboard_api.integrations.attacks_collectors.types import (
    AttacksCollectorValidationContext,
)
from cyber_dashboard_api.integrations.attacks_collectors.validators.base import (
    BaseAttacksCollectorValidator,
)
from cyber_dashboard_api.integrations.common import (
    IntegrationRequestError,
    ValidationResult,
)


class OgoValidator(BaseAttacksCollectorValidator):
    """Valide les credentials OGO."""

    provider_label = "OGO"

    def __init__(self, client: OgoClient) -> None:
        self._client = client

    def validate(
        self,
        context: AttacksCollectorValidationContext,
    ) -> ValidationResult:
        if context.api_key is None:
            return ValidationResult.fail("La clé API OGO est manquante")
        if context.email is None:
            return ValidationResult.fail("L'e-mail OGO est manquant")

        try:
            result = self._client.validate_credentials(
                email=context.email,
                api_key=context.api_key,
            )
        except IntegrationRequestError as exc:
            return self._map_request_error(exc)

        return self._map_validation_result(result)

    @staticmethod
    def _map_validation_result(
        result: OgoCredentialsValidationResult,
    ) -> ValidationResult:
        """Traduit le resultat detaille OGO vers le format de validation commun."""
        if not result.authenticated:
            return ValidationResult.fail(
                "Les identifiants OGO ont été rejetés",
                provider_status_code=result.status_code,
            )

        if not result.has_journal_access:
            return ValidationResult.fail(
                "Les identifiants OGO sont valides mais le privilège requis 'export_logs' est manquant",
                provider_status_code=result.status_code,
            )

        return ValidationResult.ok(provider_status_code=result.status_code)
