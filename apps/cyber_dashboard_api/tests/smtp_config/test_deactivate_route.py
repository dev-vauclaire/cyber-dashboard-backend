"""Tests de la route POST /api/smtp-config/deactivate."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.smtp_config import deactivate_smtp_config

from tests.smtp_config.helpers import (
    FakeSmtpConfigService,
    build_public_smtp_response,
    dump_schema,
)


class DeactivateSmtpConfigRouteTestCase(unittest.TestCase):
    """Couvre la desactivation de la configuration SMTP."""

    def test_deactivate_returns_inactive_configuration(self) -> None:
        service = FakeSmtpConfigService(
            results={
                "deactivate_config": build_public_smtp_response(
                    smtp_password_hint="****cret",
                    is_active=False,
                    last_validation_status="success",
                    has_smtp_password=True,
                )
            }
        )

        response = deactivate_smtp_config(smtp_config_service=service)

        body = dump_schema(response)
        self.assertFalse(body["is_active"])
        self.assertTrue(body["has_smtp_password"])
