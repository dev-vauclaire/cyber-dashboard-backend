"""Tests de la route DELETE /api/smtp-config/password."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.smtp_config import delete_smtp_password

from tests.smtp_config.helpers import (
    FakeSmtpConfigService,
    build_public_smtp_response,
    dump_schema,
)


class DeleteSmtpPasswordRouteTestCase(unittest.TestCase):
    """Couvre la suppression du mot de passe SMTP."""

    def test_delete_password_returns_configuration_without_password(self) -> None:
        service = FakeSmtpConfigService(
            results={
                "delete_password": build_public_smtp_response(
                    smtp_password_hint=None,
                    is_active=False,
                    last_validation_status="not_tested",
                    has_smtp_password=False,
                )
            }
        )

        response = delete_smtp_password(smtp_config_service=service)

        body = dump_schema(response)
        self.assertFalse(body["has_smtp_password"])
        self.assertIsNone(body["smtp_password_hint"])
