"""Tests de la route POST /api/attacks-collector-config/{id}/deactivate."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    deactivate_attacks_collector_config,
)
from cyber_dashboard_api.api.errors import NotFoundError

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class DeactivateAttacksCollectorConfigRouteTestCase(unittest.TestCase):
    """Couvre la desactivation d'une configuration de collecteur."""

    def test_deactivate_returns_updated_configuration(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "deactivate_config": build_config_response(
                    config_id=1,
                    is_active=False,
                    last_validation_status="success",
                )
            }
        )

        response = deactivate_attacks_collector_config(
            config_id=1,
            attacks_collector_config_service=service,
        )

        self.assertFalse(dump_schema(response)["is_active"])

    def test_deactivate_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "deactivate_config": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Attacks collector configuration not found",
                )
            }
        )

        with self.assertRaises(NotFoundError):
            deactivate_attacks_collector_config(
                config_id=99,
                attacks_collector_config_service=service,
            )
