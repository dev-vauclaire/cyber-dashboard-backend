"""Tests unitaires du validateur GreyNoise."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.integrations.common import IntegrationRequestError
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.integrations.cti.validators.greynoise_validator import (
    GREYNOISE_VALIDATION_TEST_IP,
    GreyNoiseValidator,
)


class FakeGreyNoiseClient:
    """Client GreyNoise fake pour piloter le validateur."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, str]] = []

    def validate_api_key(self, *, api_key: str, test_ip: str) -> int:
        self.calls.append(
            {
                "api_key": api_key,
                "test_ip": test_ip,
            }
        )
        if self.error is not None:
            raise self.error
        return self.status_code


class GreyNoiseValidatorTestCase(unittest.TestCase):
    """Couvre le validateur GreyNoise."""

    def test_validate_uses_known_greynoise_test_ip(self) -> None:
        client = FakeGreyNoiseClient(status_code=200)
        validator = GreyNoiseValidator(client)

        result = validator.validate(
            CtiValidationContext(
                code="greynoise",
                api_key="secret-key",
                test_ip="8.8.8.8",
            )
        )

        self.assertTrue(result.success)
        self.assertEqual(result.provider_status_code, 200)
        self.assertEqual(client.calls[0]["test_ip"], GREYNOISE_VALIDATION_TEST_IP)

    def test_validate_maps_auth_rejection(self) -> None:
        client = FakeGreyNoiseClient(
            error=IntegrationRequestError("auth_rejected", "rejected", status_code=401)
        )
        validator = GreyNoiseValidator(client)

        result = validator.validate(
            CtiValidationContext(
                code="greynoise",
                api_key="bad-key",
                test_ip="8.8.8.8",
            )
        )

        self.assertFalse(result.success)
        self.assertEqual(result.provider_status_code, 401)
        self.assertIn("rejected", str(result.message).lower())
