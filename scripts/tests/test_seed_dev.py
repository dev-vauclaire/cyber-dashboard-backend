"""Unit tests for the development database seed."""

from __future__ import annotations

from datetime import UTC
import unittest

from cyber_dashboard_database.models.enums import AttacksCollectorType
from scripts.db.dev_seed.attacks_collector_config import build_collector_config_ids
from scripts.db.dev_seed.context import REQUIRED_TABLES, load_schema_metadata
from scripts.db.dev_seed.sources import assert_unique_specialized_identities
from scripts.db.seed_dev import SeedDevError, parse_anchor_now, resolve_database_url


class SeedMetadataTests(unittest.TestCase):
    """Tests for SQLAlchemy metadata used by the seed script."""

    def test_load_schema_metadata_contains_required_tables(self) -> None:
        schema_metadata = load_schema_metadata()

        self.assertTrue(set(REQUIRED_TABLES).issubset(schema_metadata.tables))


class SeedDataInvariantTests(unittest.TestCase):
    """Tests for fixture-level invariants."""

    def test_specialized_source_identities_are_unique(self) -> None:
        assert_unique_specialized_identities()

    def test_collector_config_ids_accept_python_enum_values(self) -> None:
        ids = build_collector_config_ids(
            [
                {
                    "id": 10,
                    "collector_type": AttacksCollectorType.OGO,
                    "name": "dev-ogo-main",
                },
                {
                    "id": 11,
                    "collector_type": AttacksCollectorType.SERENICITY,
                    "name": "dev-serenicity-main",
                },
                {
                    "id": 12,
                    "collector_type": AttacksCollectorType.SERENICITY,
                    "name": "dev-serenicity-off",
                },
            ]
        )

        self.assertEqual(
            ids,
            {
                "ogo-main": 10,
                "serenicity-main": 11,
                "serenicity-disabled": 12,
            },
        )


class SeedDevCliTests(unittest.TestCase):
    """Tests for CLI parsing helpers."""

    def test_resolve_database_url_requires_non_empty_value(self) -> None:
        with self.assertRaises(SeedDevError):
            resolve_database_url("  ")

    def test_parse_anchor_now_accepts_naive_iso_datetime_as_utc(self) -> None:
        parsed = parse_anchor_now("2026-06-29T12:00:00")

        self.assertEqual(parsed.tzinfo, UTC)
        self.assertEqual(parsed.isoformat(), "2026-06-29T12:00:00+00:00")
