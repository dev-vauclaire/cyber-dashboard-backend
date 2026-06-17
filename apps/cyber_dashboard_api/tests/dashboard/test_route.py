"""Tests de la route GET /api/dashboard/overview."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from cyber_dashboard_api.api.routes.dashboard import (
    get_dashboard_overview,
    get_dashboard_topology,
)

from tests.common import dump_schema


class FakeDashboardRepository:
    """Repository fake pour la vue d'ensemble du dashboard."""

    def __init__(self) -> None:
        self.called = False
        self.topology_filters: dict[str, object] | None = None

    def get_overview_counts(self) -> dict[str, int]:
        self.called = True
        return {
            "total_attacks": 512,
            "total_common_ip_alerts": 17,
            "total_active_sources": 4,
            "total_inactive_sources": 1,
        }

    def get_topology(
        self,
        *,
        min_distinct_source_count: int = 3,
        alert_limit: int | None = None,
    ) -> dict[str, list[dict[str, object]]]:
        self.called = True
        self.topology_filters = {
            "min_distinct_source_count": min_distinct_source_count,
            "alert_limit": alert_limit,
        }
        seen_at = datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc)
        return {
            "collectors": [
                {
                    "id": 1,
                    "name": "OGO production",
                    "collector_type": "ogo",
                    "is_active": True,
                    "inventory_requested": False,
                    "last_validation_status": "success",
                    "last_validation_at": None,
                    "last_validation_error": None,
                }
            ],
            "sources": [
                {
                    "source_id": 10,
                    "source_name": "WAF Paris",
                    "source_color": "#0072CE",
                    "source_is_active": True,
                    "sensor_type_code": "waf",
                    "sensor_type_label": "WAF",
                    "collector_id": 1,
                    "collector_type": "ogo",
                    "alert_count": 4,
                    "domain_name": "example.org",
                    "external_id": None,
                    "last_inventory_at": None,
                    "last_inventory_status": "success",
                    "last_inventory_success_at": None,
                    "last_inventory_error_at": None,
                    "last_inventory_error_message": None,
                    "last_collection_status": "not_run",
                    "last_collection_success_at": None,
                    "last_collection_error_at": None,
                    "last_collection_error_message": None,
                }
            ],
            "alerts": [
                {
                    "alert_id": 100,
                    "attacker_ip": "192.0.2.10/32",
                    "distinct_source_count": 3,
                    "first_seen_at": seen_at,
                    "last_seen_at": seen_at,
                }
            ],
            "alert_links": [
                {
                    "alert_id": 100,
                    "source_id": 10,
                    "first_seen_at": seen_at,
                    "last_seen_at": seen_at,
                    "hit_count": 2,
                }
            ],
        }


class DashboardOverviewRouteTestCase(unittest.TestCase):
    """Couvre le mapping de la vue d'ensemble dashboard."""

    def test_overview_returns_typed_response(self) -> None:
        repository = FakeDashboardRepository()

        response = get_dashboard_overview(dashboard_repository=repository)

        self.assertTrue(repository.called)
        self.assertEqual(
            dump_schema(response),
            {
                "total_attacks": 512,
                "total_common_ip_alerts": 17,
                "total_active_sources": 4,
                "total_inactive_sources": 1,
            },
        )

    def test_topology_returns_collectors_and_sources(self) -> None:
        repository = FakeDashboardRepository()

        response = get_dashboard_topology(dashboard_repository=repository)

        payload = dump_schema(response)
        self.assertTrue(repository.called)
        self.assertEqual(
            repository.topology_filters,
            {"min_distinct_source_count": 3, "alert_limit": None},
        )
        self.assertEqual(payload["collectors"][0]["name"], "OGO production")
        self.assertEqual(payload["sources"][0]["alert_count"], 4)
        self.assertEqual(payload["sources"][0]["collector_type"], "ogo")
        self.assertEqual(payload["alerts"][0]["alert_id"], 100)
        self.assertEqual(payload["alerts"][0]["attacker_ip"], "192.0.2.10")
        self.assertEqual(payload["alert_links"][0]["source_id"], 10)
