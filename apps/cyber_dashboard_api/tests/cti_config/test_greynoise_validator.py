"""Tests unitaires du validateur GreyNoise."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.integrations.common import IntegrationRequestError
from cyber_dashboard_api.integrations.cti.clients.greynoise_client import (
    GreyNoiseClient,
)
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.integrations.cti.validators.greynoise_validator import (
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

    def validate_api_key(self, *, api_key: str) -> int:
        self.calls.append({"api_key": api_key})
        if self.error is not None:
            raise self.error
        return self.status_code


class FakeHttpJsonClient:
    """Client HTTP fake pour vérifier les endpoints GreyNoise utilisés."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def get_json(self, **kwargs: object) -> tuple[dict[str, str], int]:
        self.calls.append(kwargs)
        return {"message": "pong"}, 200


class GreyNoiseValidatorTestCase(unittest.TestCase):
    """Couvre le validateur GreyNoise."""

    def test_validate_uses_api_key_without_test_ip(self) -> None:
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
        self.assertEqual(client.calls, [{"api_key": "secret-key"}])

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
        self.assertIn("rejet", str(result.message).lower())


class GreyNoiseClientTestCase(unittest.TestCase):
    """Verrouille la séparation validation et enrichissement GreyNoise."""

    def setUp(self) -> None:
        self.client = GreyNoiseClient(timeout_seconds=5.0)
        self.http_client = FakeHttpJsonClient()
        self.client._http_client = self.http_client

    def test_validate_api_key_uses_ping_endpoint(self) -> None:
        status_code = self.client.validate_api_key(api_key="secret-key")

        self.assertEqual(status_code, 200)
        self.assertEqual(
            self.http_client.calls,
            [
                {
                    "url": "https://api.greynoise.io/ping",
                    "headers": {"key": "secret-key"},
                }
            ],
        )

    def test_get_ip_report_keeps_using_community_endpoint(self) -> None:
        self.client.get_ip_report(
            api_key="secret-key",
            ip_address="71.6.135.131",
        )

        self.assertEqual(
            self.http_client.calls,
            [
                {
                    "url": "https://api.greynoise.io/v3/community/71.6.135.131",
                    "headers": {"key": "secret-key"},
                }
            ],
        )
