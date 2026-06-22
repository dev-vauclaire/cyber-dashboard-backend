"""Tests unitaires du client et du validateur Shodan."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.integrations.common import IntegrationRequestError
from cyber_dashboard_api.integrations.cti.clients.shodan_client import ShodanClient
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.integrations.cti.validators.shodan_validator import (
    ShodanValidator,
)


class FakeShodanClient:
    """Client Shodan fake pour piloter le validateur."""

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
    """Client HTTP fake pour vérifier les endpoints Shodan utilisés."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def get_json(self, **kwargs: object) -> tuple[dict[str, object], int]:
        self.calls.append(kwargs)
        return {"plan": "dev"}, 200


class ShodanValidatorTestCase(unittest.TestCase):
    """Couvre le validateur Shodan."""

    def test_validate_uses_api_key_without_test_ip(self) -> None:
        client = FakeShodanClient(status_code=200)
        validator = ShodanValidator(client)

        result = validator.validate(
            CtiValidationContext(
                code="shodan",
                api_key="secret-key",
                test_ip="8.8.8.8",
            )
        )

        self.assertTrue(result.success)
        self.assertEqual(result.provider_status_code, 200)
        self.assertEqual(client.calls, [{"api_key": "secret-key"}])

    def test_validate_maps_auth_rejection(self) -> None:
        client = FakeShodanClient(
            error=IntegrationRequestError(
                "auth_rejected",
                "rejected",
                status_code=401,
            )
        )
        validator = ShodanValidator(client)

        result = validator.validate(
            CtiValidationContext(
                code="shodan",
                api_key="bad-key",
                test_ip="8.8.8.8",
            )
        )

        self.assertFalse(result.success)
        self.assertEqual(result.provider_status_code, 401)
        self.assertIn("rejet", str(result.message).lower())


class ShodanClientTestCase(unittest.TestCase):
    """Verrouille la séparation validation et enrichissement Shodan."""

    def setUp(self) -> None:
        self.client = ShodanClient(timeout_seconds=5.0)
        self.http_client = FakeHttpJsonClient()
        self.client._http_client = self.http_client

    def test_validate_api_key_uses_api_info_endpoint(self) -> None:
        status_code = self.client.validate_api_key(api_key="secret-key")

        self.assertEqual(status_code, 200)
        self.assertEqual(
            self.http_client.calls,
            [
                {
                    "url": "https://api.shodan.io/api-info",
                    "params": {"key": "secret-key"},
                }
            ],
        )

    def test_get_host_report_keeps_using_host_endpoint(self) -> None:
        self.client.get_host_report(
            api_key="secret-key",
            ip_address="8.8.8.8",
        )

        self.assertEqual(
            self.http_client.calls,
            [
                {
                    "url": "https://api.shodan.io/shodan/host/8.8.8.8",
                    "params": {"key": "secret-key"},
                }
            ],
        )
