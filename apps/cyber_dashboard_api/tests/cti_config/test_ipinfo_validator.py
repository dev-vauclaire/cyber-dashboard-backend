"""Tests unitaires du client et du validateur IPinfo."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.integrations.common import IntegrationRequestError
from cyber_dashboard_api.integrations.cti.clients.ipinfo_client import IpinfoClient
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.integrations.cti.validators.ipinfo_validator import (
    IpinfoValidator,
)


class FakeIpinfoClient:
    """Client IPinfo fake pour piloter le validateur."""

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
        self.calls.append({"api_key": api_key, "test_ip": test_ip})
        if self.error is not None:
            raise self.error
        return self.status_code


class FakeHttpJsonClient:
    """Client HTTP fake pour verifier les endpoints IPinfo utilises."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def get_json(self, **kwargs: object) -> tuple[dict[str, object], int]:
        self.calls.append(kwargs)
        return {"ip": "8.8.8.8"}, 200


class IpinfoValidatorTestCase(unittest.TestCase):
    """Couvre le validateur IPinfo."""

    def test_validate_uses_api_key_and_test_ip(self) -> None:
        client = FakeIpinfoClient(status_code=200)
        validator = IpinfoValidator(client)

        result = validator.validate(
            CtiValidationContext(
                code="ipinfo",
                api_key="secret-key",
                test_ip="8.8.8.8",
            )
        )

        self.assertTrue(result.success)
        self.assertEqual(result.provider_status_code, 200)
        self.assertEqual(
            client.calls,
            [{"api_key": "secret-key", "test_ip": "8.8.8.8"}],
        )

    def test_validate_maps_auth_rejection(self) -> None:
        client = FakeIpinfoClient(
            error=IntegrationRequestError(
                "auth_rejected",
                "rejected",
                status_code=401,
            )
        )
        validator = IpinfoValidator(client)

        result = validator.validate(
            CtiValidationContext(
                code="ipinfo",
                api_key="bad-key",
                test_ip="8.8.8.8",
            )
        )

        self.assertFalse(result.success)
        self.assertEqual(result.provider_status_code, 401)
        self.assertIn("rejet", str(result.message).lower())


class IpinfoClientTestCase(unittest.TestCase):
    """Verrouille l'endpoint IPinfo Lite utilise par le client."""

    def setUp(self) -> None:
        self.client = IpinfoClient(timeout_seconds=5.0)
        self.http_client = FakeHttpJsonClient()
        self.client._http_client = self.http_client

    def test_get_ip_report_uses_lite_endpoint(self) -> None:
        self.client.get_ip_report(
            api_key="secret-key",
            ip_address="8.8.8.8",
        )

        self.assertEqual(
            self.http_client.calls,
            [
                {
                    "url": "https://api.ipinfo.io/lite/8.8.8.8",
                    "params": {"token": "secret-key"},
                }
            ],
        )

    def test_validate_api_key_uses_test_ip(self) -> None:
        status_code = self.client.validate_api_key(
            api_key="secret-key",
            test_ip="8.8.8.8",
        )

        self.assertEqual(status_code, 200)
        self.assertEqual(
            self.http_client.calls,
            [
                {
                    "url": "https://api.ipinfo.io/lite/8.8.8.8",
                    "params": {"token": "secret-key"},
                }
            ],
        )
