from __future__ import annotations

import logging
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime

from cyber_dashboard_common_ip.config import CorrelatorConfig, DatabaseSettings
from cyber_dashboard_common_ip.domain.attack import Attack, AttackStatus
from cyber_dashboard_common_ip.domain.common_ip_alert import CommonIpAlert
from cyber_dashboard_common_ip.domain.common_ip_alert_source import CommonIpAlertSource
from cyber_dashboard_common_ip.domain.ip_address import IpAddress
from cyber_dashboard_common_ip.domain.seen_ip_registry import SeenIpRegistry
from cyber_dashboard_common_ip.services.correlator import Correlator


class FakeDatabase:
    def __init__(self) -> None:
        self.transactions_started = 0

    @contextmanager
    def transaction(self):
        self.transactions_started += 1
        yield self


class FakeAttackRepository:
    def __init__(self) -> None:
        self.claimed_batches: list[list[Attack]] = []
        self.processed_ids: list[int] = []
        self.reset_ids: list[int] = []
        self.requeued_count = 0

    def claim_pending_batch(self, limit: int) -> list[Attack]:
        return self.claimed_batches.pop(0) if self.claimed_batches else []

    def mark_processed(self, attack_id: int, *, connection=None) -> None:
        self.processed_ids.append(attack_id)

    def reset_to_pending(self, attack_id: int) -> None:
        self.reset_ids.append(attack_id)

    def requeue_processing_attacks(self) -> int:
        return self.requeued_count


class FakeAlertRepository:
    def __init__(self) -> None:
        self.persisted_alert: CommonIpAlert | None = None
        self.upserted_alerts: list[CommonIpAlert] = []
        self.upserted_sources: list[CommonIpAlertSource] = []

    def find_by_ip(self, attacker_ip: str, *, connection=None) -> CommonIpAlert | None:
        return self.persisted_alert

    def upsert_alert(self, alert: CommonIpAlert, *, connection=None) -> CommonIpAlert:
        persisted = CommonIpAlert(
            id=99 if self.persisted_alert is None else self.persisted_alert.id,
            attacker_ip=alert.attacker_ip,
            first_seen_at=alert.first_seen_at,
            last_seen_at=alert.last_seen_at,
            distinct_source_count=alert.distinct_source_count,
            status=alert.status,
        )
        self.persisted_alert = persisted
        self.upserted_alerts.append(persisted)
        return persisted

    def upsert_alert_source(
        self, alert_source: CommonIpAlertSource, *, connection=None
    ) -> None:
        self.upserted_sources.append(
            CommonIpAlertSource(
                alert_id=alert_source.alert_id,
                source_id=alert_source.source_id,
                first_seen_at=alert_source.first_seen_at,
                last_seen_at=alert_source.last_seen_at,
                hit_count=alert_source.hit_count,
            )
        )


class FakeStateLoader:
    def __init__(self, registry: SeenIpRegistry | None = None) -> None:
        self.registry = registry or SeenIpRegistry()

    def load_registry(self) -> SeenIpRegistry:
        return self.registry


class FakePerfCounter:
    def __init__(self, values: list[float]) -> None:
        self._values = list(values)

    def __call__(self) -> float:
        if not self._values:
            raise AssertionError("No more perf counter values available")
        return self._values.pop(0)


class CorrelatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = CorrelatorConfig(
            database=DatabaseSettings(
                host="localhost",
                port=5432,
                name="cyber",
                user="user",
                password="password",
            ),
            batch_size=10,
            poll_interval_seconds=0,
        )
        self.database = FakeDatabase()
        self.attack_repository = FakeAttackRepository()
        self.alert_repository = FakeAlertRepository()
        self.state_loader = FakeStateLoader()
        self.logger = logging.getLogger("correlator-tests")
        self.logger.handlers = [logging.NullHandler()]
        self.logger.propagate = False
        self.correlator = Correlator(
            self.config,
            self.database,
            self.attack_repository,
            self.alert_repository,
            self.state_loader,
            sleep_fn=lambda _: None,
            logger=self.logger,
        )

    def test_process_attack_with_new_ip_marks_processed_without_alert(self) -> None:
        attack = self._make_attack(attack_id=1, source_id=5, attacker_ip="192.0.2.10")

        self.correlator.process_attack(attack)

        self.assertEqual(self.attack_repository.processed_ids, [1])
        self.assertEqual(self.alert_repository.upserted_alerts, [])
        self.assertTrue(self.correlator._registry.contains_source("192.0.2.10", 5))

    def test_process_attack_with_same_source_without_common_ip_does_not_create_alert(
        self,
    ) -> None:
        attack = self._make_attack(attack_id=2, source_id=5, attacker_ip="192.0.2.20")
        self.correlator._registry = SeenIpRegistry(
            {
                "192.0.2.20": [
                    CommonIpAlertSource(
                        source_id=5,
                        first_seen_at=datetime(2026, 4, 15, 9, 0, 0),
                        last_seen_at=datetime(2026, 4, 15, 9, 0, 0),
                        hit_count=1,
                    )
                ]
            }
        )

        self.correlator.process_attack(attack)

        self.assertEqual(self.attack_repository.processed_ids, [2])
        self.assertEqual(self.alert_repository.upserted_alerts, [])
        self.assertEqual(
            self.correlator._registry.get_source_summaries("192.0.2.20")[
                0
            ].last_seen_at,
            attack.occurred_at,
        )
        self.assertEqual(
            self.correlator._registry.get_source_summaries("192.0.2.20")[0].hit_count,
            2,
        )

    def test_process_attack_with_new_source_creates_alert_and_source_rows(self) -> None:
        occurred_at = datetime(2026, 4, 15, 12, 0, 0)
        attack = self._make_attack(
            attack_id=3, source_id=7, attacker_ip="192.0.2.30", occurred_at=occurred_at
        )
        self.correlator._registry = SeenIpRegistry(
            {
                "192.0.2.30": [
                    CommonIpAlertSource(
                        source_id=5,
                        first_seen_at=datetime(2026, 4, 15, 11, 0, 0),
                        last_seen_at=datetime(2026, 4, 15, 11, 30, 0),
                        hit_count=2,
                    )
                ]
            }
        )

        self.correlator.process_attack(attack)

        self.assertEqual(self.attack_repository.processed_ids, [3])
        self.assertEqual(len(self.alert_repository.upserted_alerts), 1)
        self.assertEqual(
            self.alert_repository.upserted_alerts[0].distinct_source_count, 2
        )
        self.assertEqual(len(self.alert_repository.upserted_sources), 2)
        self.assertTrue(self.correlator._registry.contains_source("192.0.2.30", 7))
        self.assertEqual(
            self.alert_repository.upserted_sources[1].first_seen_at,
            occurred_at,
        )
        self.assertEqual(
            self.alert_repository.upserted_sources[1].last_seen_at,
            occurred_at,
        )
        self.assertEqual(self.alert_repository.upserted_sources[1].hit_count, 1)

    def test_process_attack_with_existing_common_ip_updates_alert_from_registry(
        self,
    ) -> None:
        attack = self._make_attack(
            attack_id=5,
            source_id=5,
            attacker_ip="192.0.2.40",
            occurred_at=datetime(2026, 4, 15, 12, 0, 0),
        )
        self.correlator._registry = SeenIpRegistry(
            {
                "192.0.2.40": [
                    CommonIpAlertSource(
                        source_id=5,
                        first_seen_at=datetime(2026, 4, 15, 10, 0, 0),
                        last_seen_at=datetime(2026, 4, 15, 11, 0, 0),
                        hit_count=2,
                    ),
                    CommonIpAlertSource(
                        source_id=7,
                        first_seen_at=datetime(2026, 4, 15, 9, 0, 0),
                        last_seen_at=datetime(2026, 4, 15, 9, 30, 0),
                        hit_count=1,
                    ),
                ]
            }
        )

        self.correlator.process_attack(attack)

        self.assertEqual(self.attack_repository.processed_ids, [5])
        self.assertEqual(len(self.alert_repository.upserted_alerts), 1)
        self.assertEqual(
            self.alert_repository.upserted_alerts[0].last_seen_at,
            datetime(2026, 4, 15, 12, 0, 0),
        )
        self.assertEqual(self.alert_repository.upserted_sources[0].source_id, 5)
        self.assertEqual(
            self.alert_repository.upserted_sources[0].last_seen_at,
            datetime(2026, 4, 15, 12, 0, 0),
        )
        self.assertEqual(self.alert_repository.upserted_sources[0].hit_count, 3)
        self.assertEqual(
            self.correlator._registry.get_source_summaries("192.0.2.40")[
                0
            ].last_seen_at,
            datetime(2026, 4, 15, 12, 0, 0),
        )

    def test_process_next_batch_resets_invalid_ip_to_pending(self) -> None:
        attack = self._make_attack(attack_id=4, source_id=5, attacker_ip="bad-ip")
        self.attack_repository.claimed_batches = [[attack]]

        processed_count = self.correlator.process_next_batch()

        self.assertEqual(processed_count, 1)
        self.assertEqual(self.attack_repository.processed_ids, [])
        self.assertEqual(self.attack_repository.reset_ids, [4])

    def test_process_next_batch_logs_average_processing_time_when_enabled(self) -> None:
        self.config = replace(self.config, compute_average_processing_time=True)
        self.correlator = Correlator(
            self.config,
            self.database,
            self.attack_repository,
            self.alert_repository,
            self.state_loader,
            sleep_fn=lambda _: None,
            perf_counter_fn=FakePerfCounter([10.0, 10.005, 20.0, 20.015]),
            logger=self.logger,
        )
        self.correlator._registry = SeenIpRegistry()
        self.attack_repository.claimed_batches = [
            [
                self._make_attack(attack_id=10, source_id=1, attacker_ip="192.0.2.101"),
                self._make_attack(attack_id=11, source_id=2, attacker_ip="192.0.2.102"),
            ]
        ]

        with self.assertLogs("correlator-tests", level="INFO") as captured_logs:
            processed_count = self.correlator.process_next_batch()

        self.assertEqual(processed_count, 2)
        self.assertIn(
            "Average IP processing time for batch: average=10.000 ms processed=2",
            captured_logs.output[-1],
        )

    @staticmethod
    def _make_attack(
        *,
        attack_id: int,
        source_id: int,
        attacker_ip: str,
        occurred_at: datetime | None = None,
    ) -> Attack:
        return Attack(
            id=attack_id,
            source_id=source_id,
            attacker_ip=IpAddress(attacker_ip),
            occurred_at=occurred_at or datetime(2026, 4, 15, 10, 0, 0),
            status=AttackStatus.PROCESSING,
        )
