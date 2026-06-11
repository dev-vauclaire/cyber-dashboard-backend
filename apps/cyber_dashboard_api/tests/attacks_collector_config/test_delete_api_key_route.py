"""Tests de la route DELETE /api/attacks-collector-config/{id}/api-key."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    delete_attacks_collector_api_key,
)
from cyber_dashboard_api.api.errors import NotFoundError

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class DeleteAttacksCollectorApiKeyRouteTestCase(unittest.TestCase):
    """Couvre la suppression de cle API d'un collecteur."""

    def test_delete_api_key_returns_updated_configuration(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "delete_api_key": build_config_response(
                    has_api_key=False,
                    api_key_hint=None,
                    is_active=False,
                )
            }
        )

        response = delete_attacks_collector_api_key(
            config_id=1,
            attacks_collector_config_service=service,
        )

        self.assertFalse(dump_schema(response)["has_api_key"])

    def test_delete_api_key_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "delete_api_key": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Attacks collector configuration not found",
                )
            }
        )

        with self.assertRaises(NotFoundError):
            delete_attacks_collector_api_key(
                config_id=11,
                attacks_collector_config_service=service,
            )
