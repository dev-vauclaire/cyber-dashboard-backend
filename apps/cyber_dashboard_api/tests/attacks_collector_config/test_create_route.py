"""Tests de la route POST /api/attacks-collector-config."""

from __future__ import annotations

import unittest

from pydantic import ValidationError

from cyber_dashboard_api.api.errors import BadRequestError
from cyber_dashboard_api.api.routes.attacks_collector_config import (
    create_attacks_collector_config,
)
from cyber_dashboard_api.api.schemas.attacks_collector_config import (
    AttacksCollectorConfigCreateRequestSchema,
)

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class CreateAttacksCollectorConfigRouteTestCase(unittest.TestCase):
    """Couvre la creation d'une configuration de collecteur."""

    def test_create_returns_created_configuration(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "create_config": build_config_response(config_id=3, name="OGO staging")
            }
        )
        payload = AttacksCollectorConfigCreateRequestSchema(
            name="OGO staging",
            collector_type="ogo",
            api_key="ogo-api-key-5678",
            email="ogo-staging@example.local",
        )

        response = create_attacks_collector_config(
            payload=payload,
            attacks_collector_config_service=service,
        )

        body = dump_schema(response)
        self.assertEqual(body["id"], 3)
        payload = service.calls[0]["args"][0]
        self.assertEqual(payload.name, "OGO staging")
        self.assertEqual(payload.email, "ogo-staging@example.local")

    def test_create_returns_bad_request_for_business_error(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "create_config": BadRequestError(
                    code="invalid_payload",
                    message="Field 'is_active' cannot be true on create",
                )
            }
        )
        payload = AttacksCollectorConfigCreateRequestSchema(
            name="OGO invalid",
            collector_type="ogo",
            api_key="ogo-api-key-5678",
            is_active=True,
        )

        with self.assertRaises(BadRequestError) as context:
            create_attacks_collector_config(
                payload=payload,
                attacks_collector_config_service=service,
            )

        self.assertEqual(context.exception.code, "invalid_payload")

    def test_create_rejects_invalid_body(self) -> None:
        with self.assertRaises(ValidationError):
            AttacksCollectorConfigCreateRequestSchema(
                collector_type="ogo",
            )
