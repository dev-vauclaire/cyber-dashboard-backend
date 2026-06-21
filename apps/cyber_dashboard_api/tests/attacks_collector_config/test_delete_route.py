"""Tests de la route DELETE /api/attacks-collector-config/{id}."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    delete_attacks_collector_config,
)
from cyber_dashboard_api.api.errors import NotFoundError

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
)


class DeleteAttacksCollectorConfigRouteTestCase(unittest.TestCase):
    """Couvre la suppression d'une configuration de collecteur."""

    def test_delete_returns_no_content(self) -> None:
        service = FakeAttacksCollectorConfigService(results={"delete_config": None})

        response = delete_attacks_collector_config(
            config_id=7,
            attacks_collector_config_service=service,
        )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.body, b"")

    def test_delete_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "delete_config": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Configuration de collecteur d'attaques introuvable",
                )
            }
        )

        with self.assertRaises(NotFoundError) as context:
            delete_attacks_collector_config(
                config_id=999,
                attacks_collector_config_service=service,
            )

        self.assertEqual(context.exception.code, "attacks_collector_config_not_found")
