"""Unit tests for the Alembic bootstrap migration script."""

from __future__ import annotations

import unittest

from scripts.migrate import (
    ALEMBIC_VERSION_TABLE,
    DatabaseInspectionResult,
    has_alembic_version_table,
    is_empty_database,
    matches_legacy_v1_schema,
    resolve_migration_plan,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
