"""Tests des routes /api/cti-config."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.api.routes.cti_config import (
    activate_cti_config,
    deactivate_cti_config,
    delete_cti_api_key,
    get_cti_config,
    list_cti_configs,
    update_cti_config,
)
from cyber_dashboard_api.api.schemas import CtiConfigUpdateRequestSchema

from tests.common import dump_schema, fixed_now


def build_cti_config(
    *,
    code: str = "rdap",
    label: str = "RDAP / WHOIS",
    is_key_required: bool = False,
    is_active: bool = False,
) -> dict[str, object]:
    """Construit une configuration CTI publique representative."""
    return {
        "id": 3,
        "code": code,
        "label": label,
        "is_key_required": is_key_required,
        "is_active": is_active,
        "has_api_key": False,
        "api_key_hint": None,
        "last_validation_status": "not_tested",
        "last_validation_at": None,
        "last_validation_error": None,
        "created_at": fixed_now(),
        "updated_at": fixed_now(),
    }


class FakeCtiConfigService:
    """Service fake pour les routes CTI."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def list_configs(self) -> list[dict[str, object]]:
        self.calls.append({"method": "list"})
        return [build_cti_config()]

    def get_config(self, code: str) -> dict[str, object]:
        self.calls.append({"method": "get", "code": code})
        if code == "missing":
            raise NotFoundError(code="cti_config_not_found", message="CTI configuration not found")
        return build_cti_config(code=code)

    def update_config(self, *, code: str, payload: object) -> dict[str, object]:
        self.calls.append({"method": "update", "code": code, "payload": payload})
        return build_cti_config(code=code, label="Updated label")

    def activate_config(self, code: str) -> dict[str, object]:
        self.calls.append({"method": "activate", "code": code})
        return build_cti_config(code=code, is_active=True)

    def deactivate_config(self, code: str) -> dict[str, object]:
        self.calls.append({"method": "deactivate", "code": code})
        return build_cti_config(code=code, is_active=False)

    def delete_api_key(self, code: str) -> dict[str, object]:
        self.calls.append({"method": "delete_api_key", "code": code})
        return build_cti_config(code=code, is_active=False)


class CtiConfigRoutesTestCase(unittest.TestCase):
    """Couvre la couche HTTP des configurations CTI."""

    def setUp(self) -> None:
        self.service = FakeCtiConfigService()

    def test_list_cti_configs_returns_items(self) -> None:
        response = list_cti_configs(cti_config_service=self.service)

        self.assertEqual(dump_schema(response)["items"][0]["code"], "rdap")

    def test_get_cti_config_returns_typed_response(self) -> None:
        response = get_cti_config(code="reverse_dns", cti_config_service=self.service)

        self.assertEqual(dump_schema(response)["code"], "reverse_dns")

    def test_get_cti_config_propagates_not_found(self) -> None:
        with self.assertRaises(NotFoundError) as context:
            get_cti_config(code="missing", cti_config_service=self.service)

        self.assertEqual(context.exception.code, "cti_config_not_found")

    def test_update_cti_config_passes_payload(self) -> None:
        payload = CtiConfigUpdateRequestSchema(label="Updated label")

        response = update_cti_config(
            payload=payload,
            code="rdap",
            cti_config_service=self.service,
        )

        self.assertEqual(dump_schema(response)["label"], "Updated label")
        self.assertEqual(self.service.calls[-1]["code"], "rdap")

    def test_activate_cti_config_returns_active_config(self) -> None:
        response = activate_cti_config(code="rdap", cti_config_service=self.service)

        self.assertTrue(dump_schema(response)["is_active"])

    def test_deactivate_cti_config_returns_inactive_config(self) -> None:
        response = deactivate_cti_config(code="rdap", cti_config_service=self.service)

        self.assertFalse(dump_schema(response)["is_active"])

    def test_delete_cti_api_key_returns_typed_config(self) -> None:
        response = delete_cti_api_key(code="rdap", cti_config_service=self.service)

        self.assertEqual(dump_schema(response)["code"], "rdap")
