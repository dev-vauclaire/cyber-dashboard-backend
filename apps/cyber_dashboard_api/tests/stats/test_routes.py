"""Tests des routes /api/stats/attacks."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from cyber_dashboard_api.api.errors import BadRequestError
from cyber_dashboard_api.api.routes.stats import (
    PARIS_TIMEZONE,
    get_attack_distribution_by_source,
    get_attack_distribution_by_type,
    get_attack_summary,
    get_attack_timeseries_by_source,
)

from tests.common import dump_schema


def build_from_to() -> tuple[datetime, datetime]:
    """Construit une plage de test stable."""
    return (
        datetime(2026, 4, 1, 0, 0, 0, tzinfo=UTC),
        datetime(2026, 4, 3, 23, 59, 59, tzinfo=UTC),
    )


class FakeStatisticsRepository:
    """Repository fake pour les routes statistiques."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def get_attack_total_between(self, *, occurred_from: object, occurred_to: object) -> int:
        self.calls.append(
            {
                "method": "total",
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            }
        )
        return 18

    def get_attack_distribution_by_source(
        self,
        *,
        occurred_from: object,
        occurred_to: object,
    ) -> list[dict[str, object]]:
        self.calls.append(
            {
                "method": "by_source",
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            }
        )
        return [
            {
                "source_id": 1,
                "source_name": "OGO Paris",
                "attack_count": 11,
                "percentage": 61.11,
            },
            {
                "source_id": 2,
                "source_name": "Lurio Lyon",
                "attack_count": 7,
                "percentage": 38.89,
            },
        ]

    def get_attack_timeseries_by_source(
        self,
        *,
        occurred_from: object,
        occurred_to: object,
    ) -> list[dict[str, object]]:
        self.calls.append(
            {
                "method": "by_source_timeseries",
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            }
        )
        paris = ZoneInfo("Europe/Paris")
        return [
            {
                "source_id": 1,
                "source_name": "OGO Paris",
                "source_color": "#2563EB",
                "source_is_active_current": False,
                "bucket_start_paris": datetime(2026, 4, 1, 0, 0, 0, tzinfo=paris),
                "bucket_attack_count": 4,
            },
            {
                "source_id": 1,
                "source_name": "OGO Paris",
                "source_color": "#2563EB",
                "source_is_active_current": False,
                "bucket_start_paris": datetime(2026, 4, 3, 0, 0, 0, tzinfo=paris),
                "bucket_attack_count": 2,
            },
            {
                "source_id": 2,
                "source_name": "Lurio Lyon",
                "source_color": "#16A34A",
                "source_is_active_current": True,
                "bucket_start_paris": datetime(2026, 4, 2, 0, 0, 0, tzinfo=paris),
                "bucket_attack_count": 3,
            },
        ]

    def get_attack_distribution_by_type(
        self,
        *,
        occurred_from: object,
        occurred_to: object,
    ) -> list[dict[str, object]]:
        self.calls.append(
            {
                "method": "by_type",
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            }
        )
        return [
            {"attack_type": "ssh_bruteforce", "attack_count": 12, "percentage": 66.67},
            {"attack_type": "http_scan", "attack_count": 6, "percentage": 33.33},
        ]


class StatisticsRoutesTestCase(unittest.TestCase):
    """Couvre les quatre routes statistiques."""

    def setUp(self) -> None:
        self.repository = FakeStatisticsRepository()
        self.from_at, self.to_at = build_from_to()

    def test_summary_returns_total_between_dates(self) -> None:
        response = get_attack_summary(
            from_at=self.from_at,
            to_at=self.to_at,
            statistics_repository=self.repository,
        )

        payload = dump_schema(response)
        self.assertEqual(payload["total_attacks"], 18)
        self.assertEqual(payload["from_at"], "2026-04-01T00:00:00Z")
        self.assertEqual(payload["to_at"], "2026-04-03T23:59:59Z")

    def test_distribution_by_source_returns_typed_items(self) -> None:
        response = get_attack_distribution_by_source(
            from_at=self.from_at,
            to_at=self.to_at,
            statistics_repository=self.repository,
        )

        payload = dump_schema(response)
        self.assertEqual(payload["total_attacks"], 18)
        self.assertEqual(payload["by_source"][0]["source_name"], "OGO Paris")
        self.assertEqual(payload["by_source"][1]["attack_count"], 7)

    def test_timeseries_by_source_returns_daily_buckets_and_series(self) -> None:
        response = get_attack_timeseries_by_source(
            from_at=self.from_at,
            to_at=self.to_at,
            statistics_repository=self.repository,
        )

        payload = dump_schema(response)
        self.assertEqual(payload["from"], "2026-04-01T00:00:00Z")
        self.assertEqual(payload["to"], "2026-04-03T23:59:59Z")
        self.assertEqual(payload["bucket"], "day")
        self.assertEqual(len(payload["bucket_starts_utc"]), 4)
        self.assertEqual(payload["series"][0]["data"], [4, 0, 2, 0])
        self.assertEqual(payload["series"][1]["data"], [0, 3, 0, 0])

    def test_distribution_by_type_returns_items(self) -> None:
        response = get_attack_distribution_by_type(
            from_at=self.from_at,
            to_at=self.to_at,
            statistics_repository=self.repository,
        )

        payload = dump_schema(response)
        self.assertEqual(payload["items"][0]["attack_type"], "ssh_bruteforce")
        self.assertEqual(payload["items"][1]["percentage"], 33.33)

    def test_summary_rejects_invalid_date_range(self) -> None:
        with self.assertRaises(BadRequestError) as context:
            get_attack_summary(
                from_at=self.to_at,
                to_at=self.from_at,
                statistics_repository=self.repository,
            )

        self.assertEqual(context.exception.code, "invalid_date_range")
