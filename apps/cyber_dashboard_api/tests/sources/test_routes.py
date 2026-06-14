"""Tests des routes /api/sources."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.api.routes.sources import (
    get_sources_inventory,
    list_sources,
    rename_source,
    update_source_color,
    update_source_status,
)
from cyber_dashboard_api.api.schemas import (
    SourceColorUpdateRequestSchema,
    SourceRenameRequestSchema,
    SourceStatusUpdateRequestSchema,
)

from tests.common import dump_schema, fixed_now


def build_source_item(
    *,
    source_id: int = 1,
    source_name: str = "OGO Paris",
    domain_name: str | None = "ogo.example.local",
    is_active: bool = True,
    sensor_type_code: str = "waf",
    sensor_type_label: str = "Web Application Firewall",
    color: str | None = "#2563EB",
) -> dict[str, object]:
    """Construit une source publique representative."""
    return {
        "source_id": source_id,
        "source_name": source_name,
        "domain_name": domain_name,
        "is_active": is_active,
        "created_at": fixed_now(),
        "sensor_type_code": sensor_type_code,
        "sensor_type_label": sensor_type_label,
        "color": color,
    }


class FakeSourceService:
    """Service fake pour les routes sources."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.inventory = [
            {
                "sensor_type_code": "waf",
                "sensor_type_label": "Web Application Firewall",
                "active_count": 2,
                "inactive_count": 1,
            }
        ]
        self.sources = [build_source_item()]
        self.renamed = build_source_item(source_name="OGO Paris PROD")
        self.status_updated = build_source_item(is_active=False)
        self.color_updated = build_source_item(color="#00FF00")

    def get_sensor_inventory(self) -> list[dict[str, object]]:
        self.calls.append({"method": "get_sensor_inventory"})
        return self.inventory

    def list_sources(self) -> list[dict[str, object]]:
        self.calls.append({"method": "list_sources"})
        return self.sources

    def rename_source(self, *, source_id: int, source_name: str) -> dict[str, object]:
        self.calls.append(
            {"method": "rename_source", "source_id": source_id, "source_name": source_name}
        )
        return self.renamed

    def update_source_status(
        self,
        *,
        source_id: int,
        is_active: bool,
    ) -> dict[str, object]:
        self.calls.append(
            {"method": "update_source_status", "source_id": source_id, "is_active": is_active}
        )
        return self.status_updated

    def update_source_color(
        self,
        *,
        source_id: int,
        color: str,
    ) -> dict[str, object]:
        self.calls.append(
            {"method": "update_source_color", "source_id": source_id, "color": color}
        )
        return self.color_updated


class SourceRoutesTestCase(unittest.TestCase):
    """Couvre les routes sources et inventaire."""

    def setUp(self) -> None:
        self.service = FakeSourceService()

    def test_inventory_returns_typed_items(self) -> None:
        response = get_sources_inventory(source_service=self.service)

        self.assertEqual(
            dump_schema(response),
            {
                "items": [
                    {
                        "sensor_type_code": "waf",
                        "sensor_type_label": "Web Application Firewall",
                        "active_count": 2,
                        "inactive_count": 1,
                    }
                ]
            },
        )

    def test_list_sources_returns_typed_items(self) -> None:
        response = list_sources(source_service=self.service)

        self.assertEqual(dump_schema(response)["items"][0]["domain_name"], "ogo.example.local")
        self.assertEqual(dump_schema(response)["items"][0]["source_name"], "OGO Paris")

    def test_rename_source_passes_payload_to_service(self) -> None:
        response = rename_source(
            payload=SourceRenameRequestSchema(source_name="OGO Paris PROD"),
            source_id=3,
            source_service=self.service,
        )

        self.assertEqual(dump_schema(response)["source_name"], "OGO Paris PROD")
        self.assertEqual(
            self.service.calls[-1],
            {
                "method": "rename_source",
                "source_id": 3,
                "source_name": "OGO Paris PROD",
            },
        )

    def test_update_source_status_passes_payload_to_service(self) -> None:
        response = update_source_status(
            payload=SourceStatusUpdateRequestSchema(is_active=False),
            source_id=4,
            source_service=self.service,
        )

        self.assertFalse(dump_schema(response)["is_active"])
        self.assertEqual(
            self.service.calls[-1],
            {
                "method": "update_source_status",
                "source_id": 4,
                "is_active": False,
            },
        )

    def test_update_source_color_passes_payload_to_service(self) -> None:
        response = update_source_color(
            payload=SourceColorUpdateRequestSchema(color="#00FF00"),
            source_id=5,
            source_service=self.service,
        )

        self.assertEqual(dump_schema(response)["color"], "#00FF00")
        self.assertEqual(
            self.service.calls[-1],
            {
                "method": "update_source_color",
                "source_id": 5,
                "color": "#00FF00",
            },
        )

    def test_route_propagates_not_found_error(self) -> None:
        class MissingSourceService(FakeSourceService):
            def rename_source(self, *, source_id: int, source_name: str) -> dict[str, object]:
                del source_id, source_name
                raise NotFoundError(
                    code="source_not_found",
                    message="Source not found",
                )

        with self.assertRaises(NotFoundError) as context:
            rename_source(
                payload=SourceRenameRequestSchema(source_name="Missing"),
                source_id=999,
                source_service=MissingSourceService(),
            )

        self.assertEqual(context.exception.code, "source_not_found")
