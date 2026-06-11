"""Validateur GreyNoise."""

from __future__ import annotations

from cyber_dashboard_api.integrations.common import IntegrationRequestError, ValidationResult
from cyber_dashboard_api.integrations.cti.clients.greynoise_client import GreyNoiseClient
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.integrations.cti.validators.base import BaseCtiValidator


GREYNOISE_VALIDATION_TEST_IP = "71.6.135.131"


class GreyNoiseValidator(BaseCtiValidator):
    """Valide les credentials GreyNoise."""

    provider_label = "GreyNoise"

    def __init__(self, client: GreyNoiseClient) -> None:
        self._client = client

    def validate(self, context: CtiValidationContext) -> ValidationResult:
        if context.api_key is None:
            return ValidationResult.fail("GreyNoise API key is missing")

        try:
            # GreyNoise Community responds more consistently on a known catalogued IP
            # than on the generic cross-provider validation IP.
            status_code = self._client.validate_api_key(
                api_key=context.api_key,
                test_ip=GREYNOISE_VALIDATION_TEST_IP,
            )
        except IntegrationRequestError as exc:
            return self._map_request_error(exc)

        return ValidationResult.ok(provider_status_code=status_code)
