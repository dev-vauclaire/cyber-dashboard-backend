"""Unit tests for the Alembic bootstrap migration script."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from scripts.db.migrate import (
    ALEMBIC_VERSION_TABLE,
    DatabaseInspectionResult,
    MigrationBootstrapError,
    has_alembic_version_table,
    is_empty_database,
    matches_legacy_v1_schema,
    resolve_migration_plan,
    wait_for_database,
)


def build_inspection(
    *,
    detected_state: str,
    has_alembic_version_table_value: bool = False,
    current_revision: str | None = None,
    is_empty: bool = False,
    matches_legacy_v1_value: bool = False,
) -> DatabaseInspectionResult:
    """Build a reusable inspection object for plan resolution tests."""
    return DatabaseInspectionResult(
        detected_state=detected_state,
        has_alembic_version_table=has_alembic_version_table_value,
        current_revision=current_revision,
        business_tables=(),
        is_empty=is_empty,
        matches_legacy_v1=matches_legacy_v1_value,
    )


class AlembicVersionDetectionTests(unittest.TestCase):
    """Tests related to Alembic version metadata detection."""

    def test_has_alembic_version_table_returns_true_when_present(self) -> None:
        self.assertTrue(
            has_alembic_version_table(
                {"sensor_types", ALEMBIC_VERSION_TABLE, "sources"}
            )
        )

    def test_has_alembic_version_table_returns_false_when_absent(self) -> None:
        self.assertFalse(has_alembic_version_table({"sensor_types", "sources"}))


class EmptyDatabaseDetectionTests(unittest.TestCase):
    """Tests for empty database detection."""

    def test_database_with_only_alembic_version_is_empty(self) -> None:
        self.assertTrue(is_empty_database({ALEMBIC_VERSION_TABLE}))

    def test_database_with_business_tables_is_not_empty(self) -> None:
        self.assertFalse(
            is_empty_database({ALEMBIC_VERSION_TABLE, "sensor_types", "sources"})
        )


class LegacyV1SchemaDetectionTests(unittest.TestCase):
    """Tests for legacy V1 schema recognition."""

    def test_matches_legacy_v1_schema_when_required_tables_and_columns_exist(
        self,
    ) -> None:
        public_tables = {
            "sensor_types",
            "sources",
            "attacks",
            "common_ip_alerts",
            "common_ip_alert_sources",
            "scheduler_state",
        }
        columns_by_table = {
            "sources": {
                "id",
                "sensor_type_id",
                "external_id",
                "name",
                "latitude",
                "longitude",
                "is_active",
                "created_at",
                "color",
            },
            "attacks": {
                "id",
                "deduplication_id",
                "source_id",
                "attacker_ip",
                "occurred_at",
                "collected_at",
                "attack_type",
                "raw_payload",
                "correlation_status",
            },
        }

        self.assertTrue(
            matches_legacy_v1_schema(
                public_tables=public_tables,
                columns_by_table=columns_by_table,
            )
        )

    def test_matches_legacy_v1_schema_returns_false_when_source_column_is_missing(
        self,
    ) -> None:
        public_tables = {
            "sensor_types",
            "sources",
            "attacks",
            "common_ip_alerts",
            "common_ip_alert_sources",
            "scheduler_state",
        }
        columns_by_table = {
            "sources": {
                "id",
                "sensor_type_id",
                "name",
                "latitude",
                "longitude",
                "is_active",
                "created_at",
                "color",
            },
            "attacks": {
                "id",
                "deduplication_id",
                "source_id",
                "attacker_ip",
                "occurred_at",
                "collected_at",
                "attack_type",
                "raw_payload",
                "correlation_status",
            },
        }

        self.assertFalse(
            matches_legacy_v1_schema(
                public_tables=public_tables,
                columns_by_table=columns_by_table,
            )
        )

    def test_matches_legacy_v1_schema_returns_false_when_required_table_is_missing(
        self,
    ) -> None:
        public_tables = {
            "sensor_types",
            "sources",
            "attacks",
            "common_ip_alerts",
            "scheduler_state",
        }
        columns_by_table = {
            "sources": {
                "id",
                "sensor_type_id",
                "external_id",
                "name",
                "latitude",
                "longitude",
                "is_active",
                "created_at",
                "color",
            },
            "attacks": {
                "id",
                "deduplication_id",
                "source_id",
                "attacker_ip",
                "occurred_at",
                "collected_at",
                "attack_type",
                "raw_payload",
                "correlation_status",
            },
        }

        self.assertFalse(
            matches_legacy_v1_schema(
                public_tables=public_tables,
                columns_by_table=columns_by_table,
            )
        )


class MigrationPlanResolutionTests(unittest.TestCase):
    """Tests for bootstrap plan selection."""

    def test_resolve_upgrade_head_for_versioned_database(self) -> None:
        inspection = build_inspection(
            detected_state="alembic_versioned",
            has_alembic_version_table_value=True,
            current_revision="14b43480c45e",
        )
        self.assertEqual(resolve_migration_plan(inspection), "upgrade_head")

    def test_resolve_upgrade_head_for_empty_database(self) -> None:
        inspection = build_inspection(
            detected_state="empty",
            is_empty=True,
        )
        self.assertEqual(resolve_migration_plan(inspection), "upgrade_head")

    def test_resolve_stamp_baseline_then_upgrade_for_legacy_v1_database(self) -> None:
        inspection = build_inspection(
            detected_state="legacy_v1",
            matches_legacy_v1_value=True,
        )
        self.assertEqual(
            resolve_migration_plan(inspection),
            "stamp_baseline_then_upgrade",
        )

    def test_resolve_abort_for_unknown_database(self) -> None:
        inspection = build_inspection(detected_state="unknown")
        self.assertEqual(
            resolve_migration_plan(inspection),
            "abort_unknown_database",
        )


class WaitForDatabaseTests(unittest.TestCase):
    """Tests for the database readiness wait loop."""

    @mock.patch.dict(
        os.environ,
        {
            "DATABASE_WAIT_TIMEOUT_SECONDS": "10",
            "DATABASE_WAIT_POLL_SECONDS": "1",
        },
        clear=False,
    )
    @mock.patch("scripts.db.migrate.time.sleep")
    @mock.patch("scripts.db.migrate.time.monotonic", side_effect=[0, 0])
    @mock.patch("scripts.db.migrate._probe_database_connection")
    def test_wait_for_database_returns_when_connection_succeeds(
        self,
        probe_connection_mock: mock.Mock,
        _monotonic_mock: mock.Mock,
        _sleep_mock: mock.Mock,
    ) -> None:
        wait_for_database("postgresql+psycopg://user:pass@db:5432/test")

        probe_connection_mock.assert_called_once_with(
            "postgresql+psycopg://user:pass@db:5432/test"
        )

    @mock.patch.dict(
        os.environ,
        {
            "DATABASE_WAIT_TIMEOUT_SECONDS": "10",
            "DATABASE_WAIT_POLL_SECONDS": "1",
        },
        clear=False,
    )
    @mock.patch("scripts.db.migrate.time.sleep")
    @mock.patch("scripts.db.migrate.time.monotonic", side_effect=[0, 0, 1])
    @mock.patch("scripts.db.migrate._probe_database_connection")
    def test_wait_for_database_retries_after_transient_connection_error(
        self,
        probe_connection_mock: mock.Mock,
        _monotonic_mock: mock.Mock,
        sleep_mock: mock.Mock,
    ) -> None:
        probe_connection_mock.side_effect = [
            MigrationBootstrapError("temporary failure in name resolution"),
            None,
        ]

        wait_for_database("postgresql+psycopg://user:pass@db:5432/test")

        self.assertEqual(probe_connection_mock.call_count, 2)
        sleep_mock.assert_called_once_with(1)

    @mock.patch.dict(
        os.environ,
        {
            "DATABASE_WAIT_TIMEOUT_SECONDS": "10",
            "DATABASE_WAIT_POLL_SECONDS": "1",
        },
        clear=False,
    )
    @mock.patch("scripts.db.migrate.time.sleep")
    @mock.patch("scripts.db.migrate.time.monotonic", side_effect=[0, 11])
    @mock.patch("scripts.db.migrate._probe_database_connection")
    def test_wait_for_database_raises_after_timeout(
        self,
        probe_connection_mock: mock.Mock,
        _monotonic_mock: mock.Mock,
        _sleep_mock: mock.Mock,
    ) -> None:
        probe_connection_mock.side_effect = MigrationBootstrapError(
            "connection refused"
        )

        with self.assertRaises(MigrationBootstrapError) as context:
            wait_for_database("postgresql+psycopg://user:pass@db:5432/test")

        self.assertIn(
            "Database did not become reachable before timeout", str(context.exception)
        )
        probe_connection_mock.assert_called_once_with(
            "postgresql+psycopg://user:pass@db:5432/test"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
