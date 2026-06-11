"""Tests de la route POST /api/smtp-config/activate."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.smtp_config import activate_smtp_config

from tests.smtp_config.helpers import (
    FakeSmtpConfigService,
    build_public_smtp_response,
    dump_schema,
)


class ActivateSmtpConfigRouteTestCase(unittest.TestCase):
    """Couvre l'activation de la configuration SMTP."""

    def test_activate_returns_public_configuration(self) -> None:
        service = FakeSmtpConfigService(
            results={
                "activate_config": build_public_smtp_response(
                    smtp_password_hint="****cret",
                    is_active=True,
                    last_validation_status="success",
                    has_smtp_password=True,
                )
            }
        )

        response = activate_smtp_config(smtp_config_service=service)

        body = dump_schema(response)
        self.assertTrue(body["is_active"])
        self.assertEqual(body["last_validation_status"], "success")
        self.assertNotIn("encrypted_smtp_password", body)
