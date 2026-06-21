"""Tests de la route PATCH /api/attacks-collector-config/{id}."""

from __future__ import annotations

import unittest

from pydantic import ValidationError

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    update_attacks_collector_config,
)
from cyber_dashboard_api.api.schemas.attacks_collector_config import (
    AttacksCollectorConfigUpdateRequestSchema,
)
from cyber_dashboard_api.api.errors import NotFoundError

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class UpdateAttacksCollectorConfigRouteTestCase(unittest.TestCase):
    """Couvre la mise a jour d'une configuration de collecteur."""

    def test_update_returns_updated_configuration(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "update_config": build_config_response(
                    config_id=1,
                    name="OGO production renamed",
                )
            }
        )
        payload = AttacksCollectorConfigUpdateRequestSchema(
            name="OGO production renamed"
        )

        response = update_attacks_collector_config(
            payload=payload,
            config_id=1,
            attacks_collector_config_service=service,
        )

        self.assertEqual(dump_schema(response)["name"], "OGO production renamed")
        self.assertEqual(service.calls[0]["kwargs"]["config_id"], 1)

    def test_update_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "update_config": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Configuration de collecteur d'attaques introuvable",
                )
            }
        )
        payload = AttacksCollectorConfigUpdateRequestSchema(name="Unknown")

        with self.assertRaises(NotFoundError) as context:
            update_attacks_collector_config(
                payload=payload,
                config_id=42,
                attacks_collector_config_service=service,
            )

        self.assertEqual(context.exception.code, "attacks_collector_config_not_found")

    def test_update_rejects_unexpected_fields(self) -> None:
        with self.assertRaises(ValidationError):
            AttacksCollectorConfigUpdateRequestSchema(
                unexpected="value",
            )
