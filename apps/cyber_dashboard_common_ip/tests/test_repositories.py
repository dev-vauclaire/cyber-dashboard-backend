from __future__ import annotations

import unittest
from datetime import datetime

from cyber_dashboard_common_ip.domain.attack import AttackStatus
from cyber_dashboard_common_ip.domain.common_ip_alert import CommonIpAlert
from cyber_dashboard_common_ip.domain.ip_address import IpAddress
from cyber_dashboard_common_ip.repositories.alert_repository import AlertRepository
from cyber_dashboard_common_ip.repositories.attack_repository import AttackRepository
from cyber_dashboard_common_ip.repositories.state_repository import StateRepository


class FakeCursor:
    def __init__(
        self,
        *,
        rows: list[dict[str, object]] | None = None,
        rowcount: int = 0,
    ) -> None:
        self.rows = rows or []
        self.rowcount = rowcount
        self.executed: list[tuple[str, dict[str, object] | None]] = []

    def execute(self, query: str, params: dict[str, object] | None = None) -> None:
        self.executed.append((query, params))

    def fetchall(self) -> list[dict[str, object]]:
        return list(self.rows)

    def fetchone(self) -> dict[str, object] | None:
        return self.rows[0] if self.rows else None

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(self, cursors: list[FakeCursor]) -> None:
        self._cursors = cursors

    def cursor(self) -> FakeCursor:
        return self._cursors.pop(0)


class FakeDatabase:
    def __init__(
        self,
        *,
        cursors: list[FakeCursor] | None = None,
        fetch_all_rows: list[dict[str, object]] | None = None,
    ) -> None:
        self.cursors = list(cursors or [])
        self.fetch_all_rows = list(fetch_all_rows or [])
        self.fetch_all_calls: list[tuple[str, dict[str, object] | None]] = []

    def transaction(self):
        class _TransactionContext:
            def __init__(self, cursors: list[FakeCursor]) -> None:
                self._connection = FakeConnection(cursors)

            def __enter__(self) -> FakeConnection:
                return self._connection

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

        return _TransactionContext(self.cursors)

    def fetch_all(
        self,
        query: str,
        params: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        self.fetch_all_calls.append((query, params))
        return list(self.fetch_all_rows)


class AttackRepositoryTests(unittest.TestCase):
    def test_claim_pending_batch_returns_processing_attacks(self) -> None:
        occurred_at = datetime(2026, 4, 15, 9, 0, 0)
        cursor = FakeCursor(
            rows=[
                {
                    "id": 1,
                    "source_id": 8,
                    "attacker_ip": "192.0.2.50",
                    "occurred_at": occurred_at,
                    "status": "processing",
                }
            ],
        )
        repository = AttackRepository(FakeDatabase(cursors=[cursor]))

        attacks = repository.claim_pending_batch(500)

        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0].id, 1)
        self.assertEqual(attacks[0].source_id, 8)
        self.assertEqual(attacks[0].status, AttackStatus.PROCESSING)
        self.assertIn("FOR UPDATE SKIP LOCKED", cursor.executed[0][0])
        self.assertEqual(
            cursor.executed[0][1],
            {
                "pending_status": "pending",
                "limit": 500,
                "processing_status": "processing",
            },
        )


class AlertRepositoryTests(unittest.TestCase):
    def test_upsert_alert_maps_database_record_to_domain_object(self) -> None:
        first_seen_at = datetime(2026, 4, 15, 8, 0, 0)
        last_seen_at = datetime(2026, 4, 15, 9, 0, 0)
        cursor = FakeCursor(
            rows=[
                {
                    "id": 12,
                    "attacker_ip": "192.0.2.60",
                    "first_seen_at": first_seen_at,
                    "last_seen_at": last_seen_at,
                    "distinct_source_count": 2,
                    "status": "open",
                }
            ],
        )
        repository = AlertRepository(FakeDatabase(cursors=[cursor]))

        alert = repository.upsert_alert(
            CommonIpAlert(
                attacker_ip=IpAddress("192.0.2.60"),
                first_seen_at=first_seen_at,
                last_seen_at=last_seen_at,
                distinct_source_count=2,
            )
        )

        self.assertEqual(alert.id, 12)
        self.assertEqual(alert.attacker_ip.normalize(), "192.0.2.60")
        self.assertEqual(alert.distinct_source_count, 2)


class StateRepositoryTests(unittest.TestCase):
    def test_load_seen_ips_groups_sources_by_ip(self) -> None:
        first_seen_at = datetime(2026, 4, 15, 8, 0, 0)
        last_seen_at = datetime(2026, 4, 15, 9, 0, 0)
        second_first_seen_at = datetime(2026, 4, 15, 10, 0, 0)
        second_last_seen_at = datetime(2026, 4, 15, 11, 0, 0)
        repository = StateRepository(
            FakeDatabase(
                fetch_all_rows=[
                    {
                        "attacker_ip": "192.0.2.70",
                        "source_id": 1,
                        "first_seen_at": first_seen_at,
                        "last_seen_at": last_seen_at,
                        "hit_count": 2,
                    },
                    {
                        "attacker_ip": "192.0.2.70",
                        "source_id": 3,
                        "first_seen_at": second_first_seen_at,
                        "last_seen_at": second_last_seen_at,
                        "hit_count": 1,
                    },
                    {
                        "attacker_ip": "198.51.100.5",
                        "source_id": 2,
                        "first_seen_at": second_first_seen_at,
                        "last_seen_at": second_last_seen_at,
                        "hit_count": 4,
                    },
                ]
            )
        )

        seen_ips = repository.load_seen_ips()

        self.assertEqual(
            [summary.source_id for summary in seen_ips["192.0.2.70"]], [1, 3]
        )
        self.assertEqual(seen_ips["192.0.2.70"][0].first_seen_at, first_seen_at)
        self.assertEqual(seen_ips["192.0.2.70"][0].last_seen_at, last_seen_at)
        self.assertEqual(seen_ips["192.0.2.70"][0].hit_count, 2)
        self.assertEqual(
            [summary.source_id for summary in seen_ips["198.51.100.5"]], [2]
        )
        self.assertEqual(seen_ips["198.51.100.5"][0].hit_count, 4)
