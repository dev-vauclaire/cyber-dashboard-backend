"""Tests de la route GET /api/attacks."""

from __future__ import annotations

import unittest
from datetime import timedelta

from cyber_dashboard_api.api.errors import BadRequestError
from cyber_dashboard_api.api.routes.attacks import list_attacks

from tests.common import dump_schema, fixed_now


class FakeAttackRepository:
    """Repository fake pour la liste paginee des attaques."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def count_attacks(
        self,
        *,
        source_id: int | None,
        sensor_type_code: str | None,
        attack_type: str | None,
        occurred_from: object,
        occurred_to: object,
    ) -> int:
        self.calls.append(
            {
                "method": "count",
                "source_id": source_id,
                "sensor_type_code": sensor_type_code,
                "attack_type": attack_type,
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            }
        )
        return 22

    def list_attacks(
        self,
        *,
        limit: int,
        offset: int,
        source_id: int | None,
        sensor_type_code: str | None,
        attack_type: str | None,
        occurred_from: object,
        occurred_to: object,
    ) -> list[dict[str, object]]:
        self.calls.append(
            {
                "method": "list",
                "limit": limit,
                "offset": offset,
                "source_id": source_id,
                "sensor_type_code": sensor_type_code,
                "attack_type": attack_type,
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            }
        )
        return [
            {
                "id": 91,
                "source_id": 7,
                "source_name": "OGO Paris",
                "sensor_type_code": "waf",
                "attacker_ip": "203.0.113.44/32",
                "occurred_at": fixed_now() - timedelta(hours=2),
                "collected_at": fixed_now() - timedelta(hours=1),
                "attack_type": "ssh_bruteforce",
            }
        ]


class AttackListRouteTestCase(unittest.TestCase):
    """Couvre le listing pagine des attaques."""

    def setUp(self) -> None:
        self.repository = FakeAttackRepository()

    def test_list_attacks_returns_typed_items_and_normalized_filters(self) -> None:
        response = list_attacks(
            page=2,
            page_size=10,
            sensor_type=" waf ",
            source_id=7,
            from_at=fixed_now() - timedelta(days=2),
            to_at=fixed_now(),
            attack_type=" ssh_bruteforce ",
            attack_repository=self.repository,
        )

        payload = dump_schema(response)
        self.assertEqual(payload["pagination"]["page"], 2)
        self.assertEqual(payload["pagination"]["page_size"], 10)
        self.assertEqual(payload["pagination"]["total_items"], 22)
        self.assertEqual(payload["items"][0]["attacker_ip"], "203.0.113.44")
        self.assertEqual(self.repository.calls[0]["sensor_type_code"], "waf")
        self.assertEqual(self.repository.calls[0]["attack_type"], "ssh_bruteforce")
        self.assertEqual(self.repository.calls[1]["offset"], 10)

    def test_list_attacks_rejects_invalid_date_range(self) -> None:
        with self.assertRaises(BadRequestError) as context:
            list_attacks(
                page=1,
                page_size=20,
                sensor_type=None,
                source_id=None,
                from_at=fixed_now(),
                to_at=fixed_now() - timedelta(days=1),
                attack_type=None,
                attack_repository=self.repository,
            )

        self.assertEqual(context.exception.code, "invalid_date_range")
