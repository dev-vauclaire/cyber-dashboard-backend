"""Validateur GreyNoise."""

from __future__ import annotations

from cyber_dashboard_api.integrations.common import (
    IntegrationRequestError,
    ValidationResult,
)
from cyber_dashboard_api.integrations.cti.clients.greynoise_client import (
    GreyNoiseClient,
)
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.integrations.cti.validators.base import BaseCtiValidator


class GreyNoiseValidator(BaseCtiValidator):
    """Valide les credentials GreyNoise."""

    provider_label = "GreyNoise"

    def __init__(self, client: GreyNoiseClient) -> None:
        self._client = client

    def validate(self, context: CtiValidationContext) -> ValidationResult:
        if context.api_key is None:
            return ValidationResult.fail("La clé API GreyNoise est manquante")

        try:
            status_code = self._client.validate_api_key(
                api_key=context.api_key,
            )
        except IntegrationRequestError as exc:
            return self._map_request_error(exc)

        return ValidationResult.ok(provider_status_code=status_code)
