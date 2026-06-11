"""Tests de la route GET /api/smtp-config."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.smtp_config import get_smtp_config

from tests.smtp_config.helpers import (
    FakeSmtpConfigService,
    build_public_smtp_response,
    dump_schema,
)


class GetSmtpConfigRouteTestCase(unittest.TestCase):
    """Couvre la lecture de la configuration SMTP publique."""

    def test_get_returns_public_config_without_secret(self) -> None:
        service = FakeSmtpConfigService(
            results={
                "get_config": build_public_smtp_response(
                    has_smtp_password=True,
                    smtp_password_hint="****cret",
                )
            }
        )

        response = get_smtp_config(smtp_config_service=service)

        payload = dump_schema(response)
        self.assertEqual(payload["smtp_host"], "smtp.example.local")
        self.assertTrue(payload["has_smtp_password"])
        self.assertNotIn("encrypted_smtp_password", payload)
