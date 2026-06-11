"""Tests de la route POST /api/attacks-collector-config/{id}/request-inventory."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    request_attacks_collector_inventory,
)
from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.api.schemas.attacks_collector_config import (
    AttacksCollectorInventoryRequestSchema,
)

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_inventory_response,
    dump_schema,
)


class RequestAttacksCollectorInventoryRouteTestCase(unittest.TestCase):
    """Couvre la demande d'inventaire d'un collecteur."""

    def test_request_inventory_without_body_uses_default_requested_by(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={"request_inventory": build_inventory_response(requested_by="api")}
        )

        response = request_attacks_collector_inventory(
            payload=None,
            config_id=1,
            attacks_collector_config_service=service,
        )

        self.assertEqual(dump_schema(response)["inventory_requested_by"], "api")
        self.assertIsNone(service.calls[0]["kwargs"]["requested_by"])

    def test_request_inventory_accepts_custom_requested_by(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "request_inventory": build_inventory_response(requested_by="front-admin")
            }
        )
        payload = AttacksCollectorInventoryRequestSchema(
            inventory_requested_by="front-admin"
        )

        response = request_attacks_collector_inventory(
            payload=payload,
            config_id=1,
            attacks_collector_config_service=service,
        )

        self.assertEqual(dump_schema(response)["inventory_requested_by"], "front-admin")
        self.assertEqual(service.calls[0]["kwargs"]["requested_by"], "front-admin")

    def test_request_inventory_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "request_inventory": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Attacks collector configuration not found",
                )
            }
        )

        with self.assertRaises(NotFoundError):
            request_attacks_collector_inventory(
                payload=None,
                config_id=88,
                attacks_collector_config_service=service,
            )
