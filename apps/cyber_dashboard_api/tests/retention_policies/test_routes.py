"""Tests des routes /api/retention-policies."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.retention_policies import (
    get_retention_policy,
    list_retention_policies,
    update_retention_policy,
)
from cyber_dashboard_api.api.schemas import RetentionPolicyUpdateRequestSchema

from tests.common import dump_schema, fixed_now


def build_retention_policy(
    *,
    policy_id: int = 1,
    target_table: str = "attacks",
    retention_days: int = 90,
    is_active: bool = True,
) -> dict[str, object]:
    """Construit une politique de retention representative."""
    return {
        "id": policy_id,
        "target_table": target_table,
        "retention_days": retention_days,
        "is_active": is_active,
        "last_run_at": None,
        "last_deleted_count": None,
        "last_error": None,
        "created_at": fixed_now(),
        "updated_at": fixed_now(),
    }


class FakeRetentionPolicyService:
    """Service fake pour les routes de retention."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def list_policies(self) -> list[dict[str, object]]:
        self.calls.append({"method": "list"})
        return [build_retention_policy()]

    def get_policy(self, target_table: str) -> dict[str, object]:
        self.calls.append({"method": "get", "target_table": target_table})
        return build_retention_policy(target_table=target_table)

    def update_policy(self, *, target_table: str, payload: object) -> dict[str, object]:
        self.calls.append(
            {
                "method": "update",
                "target_table": target_table,
                "payload": payload,
            }
        )
        return build_retention_policy(
            target_table=target_table,
            retention_days=30,
            is_active=False,
        )


class RetentionPolicyRoutesTestCase(unittest.TestCase):
    """Couvre les routes de retention."""

    def setUp(self) -> None:
        self.service = FakeRetentionPolicyService()

    def test_list_retention_policies_returns_items(self) -> None:
        response = list_retention_policies(retention_policy_service=self.service)

        self.assertEqual(dump_schema(response)["items"][0]["target_table"], "attacks")

    def test_get_retention_policy_returns_requested_target(self) -> None:
        response = get_retention_policy(
            target_table="common_ip_alerts",
            retention_policy_service=self.service,
        )

        self.assertEqual(dump_schema(response)["target_table"], "common_ip_alerts")

    def test_update_retention_policy_passes_payload_to_service(self) -> None:
        payload = RetentionPolicyUpdateRequestSchema(retention_days=30, is_active=False)

        response = update_retention_policy(
            payload=payload,
            target_table="attacks",
            retention_policy_service=self.service,
        )

        self.assertEqual(dump_schema(response)["retention_days"], 30)
        self.assertEqual(self.service.calls[-1]["target_table"], "attacks")
