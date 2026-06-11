"""Tests de la route POST /api/attacks-collector-config/{id}/activate."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    activate_attacks_collector_config,
)
from cyber_dashboard_api.api.errors import BadRequestError, NotFoundError

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class ActivateAttacksCollectorConfigRouteTestCase(unittest.TestCase):
    """Couvre l'activation d'une configuration de collecteur."""

    def test_activate_returns_activated_configuration(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "activate_config": build_config_response(
                    config_id=1,
                    is_active=True,
                    last_validation_status="success",
                )
            }
        )

        response = activate_attacks_collector_config(
            config_id=1,
            attacks_collector_config_service=service,
        )

        payload = dump_schema(response)
        self.assertTrue(payload["is_active"])
        self.assertEqual(payload["last_validation_status"], "success")

    def test_activate_returns_bad_request_when_validation_fails(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "activate_config": BadRequestError(
                    code="attacks_collector_validation_failed",
                    message="OGO credentials were rejected",
                )
            }
        )

        with self.assertRaises(BadRequestError) as context:
            activate_attacks_collector_config(
                config_id=1,
                attacks_collector_config_service=service,
            )

        self.assertEqual(
            context.exception.code,
            "attacks_collector_validation_failed",
        )

    def test_activate_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "activate_config": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Attacks collector configuration not found",
                )
            }
        )

        with self.assertRaises(NotFoundError):
            activate_attacks_collector_config(
                config_id=123,
                attacks_collector_config_service=service,
            )
