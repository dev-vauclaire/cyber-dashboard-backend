"""Tests de la route GET /api/attacks-collector-config."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    list_attacks_collector_configs,
)

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class ListAttacksCollectorConfigRouteTestCase(unittest.TestCase):
    """Couvre la liste des configurations de collecteurs."""

    def test_list_returns_configurations(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "list_configs": [
                    build_config_response(config_id=1, name="OGO production"),
                    build_config_response(
                        config_id=2,
                        name="Serenicity production",
                        collector_type="serenicity",
                        has_email=False,
                        email_hint=None,
                    ),
                ]
            }
        )

        response = list_attacks_collector_configs(
            attacks_collector_config_service=service,
        )

        payload = dump_schema(response)
        self.assertEqual(len(payload["items"]), 2)
        self.assertEqual(payload["items"][0]["name"], "OGO production")
        self.assertEqual(payload["items"][1]["collector_type"], "serenicity")
