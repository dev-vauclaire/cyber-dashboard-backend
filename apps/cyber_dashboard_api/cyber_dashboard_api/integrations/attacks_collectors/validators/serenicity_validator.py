"""Validateur Serenicity."""

from __future__ import annotations

from cyber_dashboard_api.integrations.attacks_collectors.clients.serenicity_client import (
    SerenicityClient,
)
from cyber_dashboard_api.integrations.attacks_collectors.types import (
    AttacksCollectorValidationContext,
)
from cyber_dashboard_api.integrations.attacks_collectors.validators.base import (
    BaseAttacksCollectorValidator,
)
from cyber_dashboard_api.integrations.common import IntegrationRequestError, ValidationResult


class SerenicityValidator(BaseAttacksCollectorValidator):
    """Valide les credentials Serenicity."""

    provider_label = "Serenicity"

    def __init__(self, client: SerenicityClient) -> None:
        self._client = client

    def validate(
        self,
        context: AttacksCollectorValidationContext,
    ) -> ValidationResult:
        if context.api_key is None:
            return ValidationResult.fail("La clé API Serenicity est manquante")

        try:
            status_code = self._client.validate_credentials(api_key=context.api_key)
        except IntegrationRequestError as exc:
            return self._map_request_error(exc)

        return ValidationResult.ok(provider_status_code=status_code)
