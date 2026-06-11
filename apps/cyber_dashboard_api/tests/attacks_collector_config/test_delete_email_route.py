"""Tests de la route DELETE /api/attacks-collector-config/{id}/email."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.attacks_collector_config import (
    delete_attacks_collector_email,
)
from cyber_dashboard_api.api.errors import NotFoundError

from tests.attacks_collector_config.helpers import (
    FakeAttacksCollectorConfigService,
    build_config_response,
    dump_schema,
)


class DeleteAttacksCollectorEmailRouteTestCase(unittest.TestCase):
    """Couvre la suppression de l'email d'un collecteur."""

    def test_delete_email_returns_updated_configuration(self) -> None:
        service = FakeAttacksCollectorConfigService(
            results={
                "delete_email": build_config_response(
                    has_email=False,
                    email_hint=None,
                    is_active=False,
                )
            }
        )

        response = delete_attacks_collector_email(
            config_id=1,
            attacks_collector_config_service=service,
        )

        self.assertFalse(dump_schema(response)["has_email"])

    def test_delete_email_returns_not_found_when_config_is_missing(self) -> None:
        service = FakeAttacksCollectorConfigService(
            errors={
                "delete_email": NotFoundError(
                    code="attacks_collector_config_not_found",
                    message="Attacks collector configuration not found",
                )
            }
        )

        with self.assertRaises(NotFoundError):
            delete_attacks_collector_email(
                config_id=55,
                attacks_collector_config_service=service,
            )
