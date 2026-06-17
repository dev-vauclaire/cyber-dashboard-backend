"""Tests de la route POST /api/smtp-config/test."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.smtp_config import test_smtp_config

from tests.smtp_config.helpers import (
    FakeSmtpConfigService,
    build_public_smtp_response,
    dump_schema,
)


class TestSmtpConfigRouteTestCase(unittest.TestCase):
    """Couvre le test de la configuration SMTP sans activation."""

    def test_test_returns_public_configuration(self) -> None:
        service = FakeSmtpConfigService(
            results={
                "test_config": build_public_smtp_response(
                    smtp_password_hint="****cret",
                    is_active=False,
                    last_validation_status="success",
                    has_smtp_password=True,
                )
            }
        )

        response = test_smtp_config(smtp_config_service=service)

        body = dump_schema(response)
        self.assertFalse(body["is_active"])
        self.assertEqual(body["last_validation_status"], "success")
        self.assertNotIn("encrypted_smtp_password", body)
