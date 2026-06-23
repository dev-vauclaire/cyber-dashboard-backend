"""Tests de la route GET /api/attacks-collector-config/{id}."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    get_attacks_collector_config,
)
from cyber_dashboard_api.api.errors import NotFoundError

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class GetAttacksCollectorConfigRouteTestCase(unittest.TestCase):
    """Couvre la lecture d'une configuration de collecteur."""

    def test_get_returns_configuration(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "get_config": build_config_response(config_id=4, name="OGO prod 4")
            }
        )

        response = get_attacks_collector_config(
            config_id=4,
            attacks_collector_config_service=service,
        )

        self.assertEqual(dump_schema(response)["id"], 4)

    def test_get_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "get_config": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Configuration de collecteur d'attaques introuvable",
                )
            }
        )

        with self.assertRaises(NotFoundError) as context:
            get_attacks_collector_config(
                config_id=999,
                attacks_collector_config_service=service,
            )

        self.assertEqual(context.exception.code, "attacks_collector_config_not_found")
