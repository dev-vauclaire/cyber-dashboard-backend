"""Validateur IPData."""

from __future__ import annotations

from cyber_dashboard_api.integrations.common import (
    IntegrationRequestError,
    ValidationResult,
)
from cyber_dashboard_api.integrations.cti.clients.ipdata_client import IpDataClient
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.integrations.cti.validators.base import BaseCtiValidator


class IpDataValidator(BaseCtiValidator):
    """Valide les credentials IPData."""

    provider_label = "IPData"

    def __init__(self, client: IpDataClient) -> None:
        self._client = client

    def validate(self, context: CtiValidationContext) -> ValidationResult:
        if context.api_key is None:
            return ValidationResult.fail("La clé API IPData est manquante")

        try:
            status_code = self._client.validate_api_key(
                api_key=context.api_key,
                test_ip=context.test_ip,
            )
        except IntegrationRequestError as exc:
            return self._map_request_error(exc)

        return ValidationResult.ok(provider_status_code=status_code)
