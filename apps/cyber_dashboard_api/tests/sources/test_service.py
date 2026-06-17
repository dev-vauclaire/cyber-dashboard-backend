"""Tests unitaires du service des sources."""

from __future__ import annotations

import unittest
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.services import SensorTypeService, SourceService


def fixed_now() -> datetime:
    """Horodatage stable pour les assertions."""
    return datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)


def build_source_row(
    *,
    source_id: int = 1,
    name: str = "Suricata",
    external_id: str | None = "https://sensor.local",
    domain_name: str | None = None,
    is_active: bool = True,
    sensor_type_code: str = "ids",
    sensor_type_label: str = "IDS",
    color: str | None = "#FF0000",
) -> dict[str, Any]:
    """Construit une ligne de source representative."""
    return {
        "id": source_id,
        "external_id": external_id,
        "domain_name": domain_name,
        "name": name,
        "is_active": is_active,
        "created_at": fixed_now(),
        "sensor_type_code": sensor_type_code,
        "sensor_type_label": sensor_type_label,
        "color": color,
    }


class FakeSourceRepository:
    """Repository minimal en memoire pour les tests du service."""

    def __init__(self) -> None:
        self.inventory_rows = [
            {
                "sensor_type_code": "ids",
                "sensor_type_label": "IDS",
                "active_sources": 2,
                "inactive_sources": 1,
            }
        ]
        self.source_rows = [build_source_row()]
        self.rename_result: dict[str, Any] | None = build_source_row(name="Suricata PROD")
        self.status_result: dict[str, Any] | None = build_source_row(is_active=False)
        self.color_result: dict[str, Any] | None = build_source_row(color="#00FF00")

    def get_sensor_inventory(self) -> list[dict[str, Any]]:
        return deepcopy(self.inventory_rows)

    def list_sources(self) -> list[dict[str, Any]]:
        return deepcopy(self.source_rows)

    def rename_source(self, *, source_id: int, source_name: str) -> dict[str, Any] | None:
        del source_id, source_name
        return deepcopy(self.rename_result)

    def update_source_status(
        self,
        *,
        source_id: int,
        is_active: bool,
    ) -> dict[str, Any] | None:
        del source_id, is_active
        return deepcopy(self.status_result)

    def update_source_color(
        self,
        *,
        source_id: int,
        color: str,
    ) -> dict[str, Any] | None:
        del source_id, color
        return deepcopy(self.color_result)


class FakeSensorTypeRepository:
    """Repository minimal en memoire pour les tests du service sensor types."""

    def __init__(self) -> None:
        self.rename_result: dict[str, Any] | None = {
            "id": 2,
            "code": "waf",
            "label": "WAF PROD",
            "category": "network",
            "color": "#2563EB",
        }
        self.calls: list[dict[str, object]] = []

    def rename_sensor_type(
        self,
        *,
        sensor_type_id: int,
        label: str,
    ) -> dict[str, Any] | None:
        self.calls.append(
            {
                "method": "rename_sensor_type",
                "sensor_type_id": sensor_type_id,
                "label": label,
            }
        )
        return deepcopy(self.rename_result)


class SourceServiceTestCase(unittest.TestCase):
    """Couvre la projection publique et les cas d'erreur du service des sources."""

    def setUp(self) -> None:
        self.repository = FakeSourceRepository()
        self.service = SourceService(self.repository)

    def test_get_sensor_inventory_maps_counts(self) -> None:
        items = self.service.get_sensor_inventory()

        self.assertEqual(
            items,
            [
                {
                    "sensor_type_code": "ids",
                    "sensor_type_label": "IDS",
                    "active_count": 2,
                    "inactive_count": 1,
                }
            ],
        )

    def test_list_sources_returns_public_shape(self) -> None:
        self.repository.source_rows = [
            build_source_row(
                name="OGO GHT Dordogne",
                external_id=None,
                domain_name="ogo.example.local",
                sensor_type_code="ogo",
                sensor_type_label="OGO",
            )
        ]
        items = self.service.list_sources()

        self.assertEqual(items[0]["source_id"], 1)
        self.assertEqual(items[0]["source_name"], "OGO GHT Dordogne")
        self.assertEqual(
            items[0]["domain_name"],
            "ogo.example.local",
        )
        self.assertEqual(items[0]["sensor_type_label"], "OGO")
        self.assertNotIn("source_external_id", items[0])

    def test_rename_source_raises_not_found_when_missing(self) -> None:
        self.repository.rename_result = None

        with self.assertRaises(NotFoundError) as context:
            self.service.rename_source(source_id=99, source_name="Unknown")

        self.assertEqual(context.exception.code, "source_not_found")

    def test_update_status_returns_public_shape(self) -> None:
        self.repository.status_result = build_source_row(
            name="OGO GHT Dordogne",
            external_id=None,
            domain_name="ogo.example.local",
            is_active=False,
            sensor_type_code="ogo",
            sensor_type_label="OGO",
        )
        item = self.service.update_source_status(source_id=1, is_active=False)

        self.assertFalse(item["is_active"])
        self.assertEqual(item["source_id"], 1)
        self.assertEqual(
            item["domain_name"],
            "ogo.example.local",
        )
        self.assertNotIn("source_external_id", item)

    def test_update_color_returns_public_shape(self) -> None:
        self.repository.color_result = build_source_row(
            name="OGO GHT Dordogne",
            external_id=None,
            domain_name="ogo.example.local",
            color="#00FF00",
            sensor_type_code="ogo",
            sensor_type_label="OGO",
        )
        item = self.service.update_source_color(source_id=1, color="#00FF00")

        self.assertEqual(item["color"], "#00FF00")
        self.assertEqual(item["source_name"], "OGO GHT Dordogne")
        self.assertEqual(
            item["domain_name"],
            "ogo.example.local",
        )
        self.assertNotIn("source_external_id", item)

    def test_rename_source_returns_public_shape_with_domain_name(self) -> None:
        self.repository.rename_result = build_source_row(
            name="OGO GHT Dordogne PROD",
            external_id=None,
            domain_name="ogo.example.local",
            sensor_type_code="ogo",
            sensor_type_label="OGO",
        )

        item = self.service.rename_source(
            source_id=1,
            source_name="OGO GHT Dordogne PROD",
        )

        self.assertEqual(item["source_name"], "OGO GHT Dordogne PROD")
        self.assertEqual(
            item["domain_name"],
            "ogo.example.local",
        )
        self.assertNotIn("source_external_id", item)


class SensorTypeServiceTestCase(unittest.TestCase):
    """Couvre la projection publique et les erreurs du service sensor types."""

    def setUp(self) -> None:
        self.repository = FakeSensorTypeRepository()
        self.service = SensorTypeService(self.repository)

    def test_rename_sensor_type_returns_public_shape(self) -> None:
        item = self.service.rename_sensor_type(sensor_type_id=2, label="WAF PROD")

        self.assertEqual(
            item,
            {
                "sensor_type_id": 2,
                "sensor_type_code": "waf",
                "sensor_type_label": "WAF PROD",
                "sensor_type_category": "network",
                "color": "#2563EB",
            },
        )
        self.assertEqual(
            self.repository.calls[-1],
            {
                "method": "rename_sensor_type",
                "sensor_type_id": 2,
                "label": "WAF PROD",
            },
        )

    def test_rename_sensor_type_raises_not_found_when_missing(self) -> None:
        self.repository.rename_result = None

        with self.assertRaises(NotFoundError) as context:
            self.service.rename_sensor_type(sensor_type_id=99, label="Missing")

        self.assertEqual(context.exception.code, "sensor_type_not_found")
