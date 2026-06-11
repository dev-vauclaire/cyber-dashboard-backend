"""Tests des routes PUT/PATCH /api/smtp-config."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.smtp_config import router, update_smtp_config
from cyber_dashboard_api.api.schemas.smtp_config import SmtpConfigUpdateRequestSchema

from tests.smtp_config.helpers import (
    FakeSmtpConfigService,
    build_public_smtp_response,
    dump_schema,
)


class UpdateSmtpConfigRouteTestCase(unittest.TestCase):
    """Couvre la mise a jour de la configuration SMTP."""

    def test_router_exposes_put_and_patch_methods(self) -> None:
        methods: set[str] = set()
        for route in router.routes:
            if getattr(route, "path", None) == "/api/smtp-config":
                methods.update(route.methods or set())

        self.assertIn("PUT", methods)
        self.assertIn("PATCH", methods)

    def test_update_returns_public_configuration(self) -> None:
        service = FakeSmtpConfigService(
            results={
                "update_config": build_public_smtp_response(
                    smtp_from_name="Cyber Dashboard Ops",
                    has_smtp_password=True,
                    smtp_password_hint="****cret",
                )
            }
        )
        payload = SmtpConfigUpdateRequestSchema(smtp_from_name="Cyber Dashboard Ops")

        response = update_smtp_config(payload=payload, smtp_config_service=service)

        body = dump_schema(response)
        self.assertEqual(body["smtp_from_name"], "Cyber Dashboard Ops")
        self.assertTrue(body["has_smtp_password"])
        self.assertNotIn("encrypted_smtp_password", body)
