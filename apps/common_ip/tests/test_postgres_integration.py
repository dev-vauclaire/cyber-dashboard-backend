from __future__ import annotations

import os
import logging
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import create_engine

from common_ip_correlator.config import ConfigurationError, CorrelatorConfig
from common_ip_correlator.db import PostgresDatabase
from common_ip_correlator.repositories.alert_repository import AlertRepository
from common_ip_correlator.repositories.attack_repository import AttackRepository
from common_ip_correlator.repositories.state_repository import StateRepository
from common_ip_correlator.services.correlator import Correlator
from common_ip_correlator.services.state_loader import StateLoader

from packages.database.models import (
    Attack as AttackModel,
    AttacksCollectorConfig,
    CommonIpAlert,
    CommonIpAlertSource,
    SensorType,
    Source,
)

try:
    import psycopg
except (
    ModuleNotFoundError
):  # pragma: no cover - the suite is skipped if psycopg is missing.
    psycopg = None


class PostgresIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if psycopg is None:
            raise unittest.SkipTest("psycopg is not installed")

        if not any(
            os.getenv(name)
            for name in ("DB_HOST", "CORRELATOR_DB_HOST", "POSTGRES_HOST", "PGHOST")
        ):
            raise unittest.SkipTest(
                "Missing PostgreSQL integration environment variables"
            )

        try:
            cls.config = CorrelatorConfig.from_env()
            cls.config.validate()
        except ConfigurationError as exc:
            raise unittest.SkipTest(str(exc)) from exc

        cls.database = PostgresDatabase(cls.config.database)
        cls.attack_repository = AttackRepository(cls.database)
        cls.alert_repository = AlertRepository(cls.database)
        cls.state_repository = StateRepository(cls.database)
        cls.state_loader = StateLoader(cls.state_repository)
        cls.engine = create_engine(
            (
                "postgresql+psycopg://"
                f"{cls.config.database.user}:{cls.config.database.password}"
                f"@{cls.config.database.host}:{cls.config.database.port}/{cls.config.database.name}"
            )
        )

    def setUp(self) -> None:
        self._reset_schema()
        self.correlator = Correlator(
            self.config,
            self.database,
            self.attack_repository,
            self.alert_repository,
            self.state_loader,
            sleep_fn=lambda _: None,
            logger=self._build_test_logger(),
        )
        self.correlator._registry = self.state_loader.load_registry()

    def test_claim_pending_batch_marks_rows_processing(self) -> None:
        self._insert_source(1)
        self._insert_attack(
            source_id=1,
            source_event_id="evt-1",
            attacker_ip="192.0.2.10",
            occurred_at=datetime(2026, 4, 15, 10, 0, 0, tzinfo=UTC),
            correlation_status="pending",
        )

        attacks = self.attack_repository.claim_pending_batch(10)

        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0].status.value, "processing")
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT correlation_status FROM attacks WHERE id = %s;",
                (attacks[0].id,),
            )
            self.assertEqual(cursor.fetchone()[0], "processing")

    def test_load_seen_ips_uses_completed_attacks(self) -> None:
        self._insert_source(1)
        self._insert_source(2)
        self._insert_attack(
            source_id=1,
            source_event_id="evt-completed-1",
            attacker_ip="198.51.100.10",
            occurred_at=datetime(2026, 4, 15, 10, 0, 0, tzinfo=UTC),
            correlation_status="completed",
        )
        self._insert_attack(
            source_id=2,
            source_event_id="evt-completed-2",
            attacker_ip="198.51.100.10",
            occurred_at=datetime(2026, 4, 15, 11, 0, 0, tzinfo=UTC),
            correlation_status="completed",
        )

        seen_ips = self.state_repository.load_seen_ips()

        self.assertEqual(
            [summary.source_id for summary in seen_ips["198.51.100.10"]], [1, 2]
        )
        self.assertEqual(
            seen_ips["198.51.100.10"][0].first_seen_at,
            datetime(2026, 4, 15, 10, 0, 0, tzinfo=UTC),
        )
        self.assertEqual(
            seen_ips["198.51.100.10"][1].last_seen_at,
            datetime(2026, 4, 15, 11, 0, 0, tzinfo=UTC),
        )

    def test_correlator_creates_alerts_for_ip_seen_on_two_sources(self) -> None:
        self._insert_source(1)
        self._insert_source(2)
        self._insert_attack(
            source_id=1,
            source_event_id="evt-common-1",
            attacker_ip="203.0.113.10",
            occurred_at=datetime(2026, 4, 15, 10, 0, 0, tzinfo=UTC),
            correlation_status="pending",
        )
        self._insert_attack(
            source_id=2,
            source_event_id="evt-common-2",
            attacker_ip="203.0.113.10",
            occurred_at=datetime(2026, 4, 15, 11, 0, 0, tzinfo=UTC),
            correlation_status="pending",
        )

        processed_count = self.correlator.process_next_batch()

        self.assertEqual(processed_count, 2)
        with self._cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM common_ip_alerts;")
            self.assertEqual(cursor.fetchone()[0], 1)
            cursor.execute("""
                SELECT attacker_ip, distinct_source_count, status
                FROM common_ip_alerts;
                """)
            attacker_ip, distinct_source_count, status = cursor.fetchone()
            self.assertEqual(attacker_ip, "203.0.113.10")
            self.assertEqual(distinct_source_count, 2)
            self.assertEqual(status, "open")

            cursor.execute("SELECT COUNT(*) FROM common_ip_alert_sources;")
            self.assertEqual(cursor.fetchone()[0], 2)
            cursor.execute(
                "SELECT COUNT(*) FROM attacks WHERE correlation_status = 'completed';"
            )
            self.assertEqual(cursor.fetchone()[0], 2)

    def test_same_source_does_not_create_common_ip_alert(self) -> None:
        self._insert_source(1)
        self._insert_attack(
            source_id=1,
            source_event_id="evt-same-source-1",
            attacker_ip="203.0.113.50",
            occurred_at=datetime(2026, 4, 15, 10, 0, 0, tzinfo=UTC),
            correlation_status="pending",
        )
        self._insert_attack(
            source_id=1,
            source_event_id="evt-same-source-2",
            attacker_ip="203.0.113.50",
            occurred_at=datetime(2026, 4, 15, 11, 0, 0, tzinfo=UTC),
            correlation_status="pending",
        )

        processed_count = self.correlator.process_next_batch()

        self.assertEqual(processed_count, 2)
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM attacks WHERE correlation_status = 'completed';"
            )
            self.assertEqual(cursor.fetchone()[0], 2)
            cursor.execute("SELECT COUNT(*) FROM common_ip_alerts;")
            self.assertEqual(cursor.fetchone()[0], 0)

    def _reset_schema(self) -> None:
        tables = [
            CommonIpAlertSource.__table__,
            CommonIpAlert.__table__,
            AttackModel.__table__,
            Source.__table__,
            SensorType.__table__,
            AttacksCollectorConfig.__table__,
        ]
        with self.engine.begin() as connection:
            for table in tables:
                table.drop(connection, checkfirst=True)
            for table in reversed(tables):
                table.create(connection, checkfirst=True)

    @staticmethod
    def _build_test_logger() -> logging.Logger:
        logger = logging.getLogger("postgres-integration-tests")
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
        return logger

    def _insert_source(self, source_id: int) -> None:
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO sensor_types (id, code, label, category, color)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING;
                """,
                (
                    1,
                    "waf",
                    "WAF",
                    "protection",
                    "#FF0000",
                ),
            )
            cursor.execute(
                """
                INSERT INTO sources (id, sensor_type_id, name, color)
                VALUES (%s, %s, %s, %s);
                """,
                (source_id, 1, f"source-{source_id}", "#FF0000"),
            )

    def _insert_attack(
        self,
        *,
        source_id: int,
        source_event_id: str,
        attacker_ip: str,
        occurred_at: datetime,
        correlation_status: str,
    ) -> None:
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO attacks (
                    deduplication_id,
                    source_id,
                    source_event_id,
                    attacker_ip,
                    occurred_at,
                    correlation_status
                )
                VALUES (%s, %s, %s, %s, %s, %s);
                """,
                (
                    f"{source_id}-{source_event_id}",
                    source_id,
                    source_event_id,
                    attacker_ip,
                    occurred_at,
                    correlation_status,
                ),
            )

    @contextmanager
    def _cursor(self, *, autocommit: bool = False):
        connection = psycopg.connect(
            host=self.config.database.host,
            port=self.config.database.port,
            dbname=self.config.database.name,
            user=self.config.database.user,
            password=self.config.database.password,
            autocommit=autocommit,
        )
        try:
            with connection.cursor() as cursor:
                yield cursor
            if not autocommit:
                connection.commit()
        except Exception:
            if not autocommit:
                connection.rollback()
            raise
        finally:
            connection.close()
