"""Tests de la route GET /api/dashboard/overview."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.dashboard import get_dashboard_overview

from tests.common import dump_schema


class FakeDashboardRepository:
    """Repository fake pour la vue d'ensemble du dashboard."""

    def __init__(self) -> None:
        self.called = False

    def get_overview_counts(self) -> dict[str, int]:
        self.called = True
        return {
            "total_attacks": 512,
            "total_common_ip_alerts": 17,
            "total_active_sources": 4,
            "total_inactive_sources": 1,
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
