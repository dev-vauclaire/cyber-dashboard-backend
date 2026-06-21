"""Tests unitaires des regles metier CTI."""

from __future__ import annotations

import base64
import unittest
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime

from cyber_dashboard_api.api.errors import BadRequestError
from cyber_dashboard_api.api.schemas.cti_config import CtiConfigUpdateRequestSchema
from cyber_dashboard_api.config import SecretSettings, ValidationSettings
from cyber_dashboard_api.integrations.common import ValidationResult
from cyber_dashboard_api.services import CtiConfigService, SecretService


def build_valid_fernet_key() -> str:
    """Construit une cle Fernet valide sans dependance externe."""
    return base64.urlsafe_b64encode(b"2" * 32).decode("utf-8")


def build_secret_service() -> SecretService:
    """Construit le service de secrets utilise dans les tests CTI."""
    return SecretService(
        SecretSettings(
            secret_key_file=None,
            secret_key=build_valid_fernet_key(),
        )
    )


def build_validation_settings() -> ValidationSettings:
    """Construit les settings minimaux attendus par le service CTI."""
    return ValidationSettings(
        timeout_seconds=5.0,
        test_ip="8.8.8.8",
        ogo_base_url=None,
        serenicity_base_url=None,
    )


def fixed_now() -> datetime:
    """Horodatage stable pour les fakes."""
    return datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)


def build_cti_row(
    *,
    code: str = "abuseipdb",
    label: str = "AbuseIPDB",
    is_key_required: bool = True,
) -> dict[str, object]:
    """Construit une ligne CTI representative."""
    return {
        "id": 1,
        "code": code,
        "label": label,
        "is_key_required": is_key_required,
        "encrypted_api_key": None,
        "api_key_hint": None,
        "is_active": False,
        "last_validation_status": "not_tested",
        "last_validation_at": None,
        "last_validation_error": None,
        "created_at": fixed_now(),
        "updated_at": fixed_now(),
    }


@dataclass
class FakeValidator:
    """Validateur fake qui memorise le contexte recu."""

    result: ValidationResult
    last_context: object | None = None

    def validate(self, context: object) -> ValidationResult:
        self.last_context = context
        return self.result


class FakeCtiValidatorRegistry:
    """Registry fake pour piloter les validateurs CTI."""

    def __init__(self, mapping: dict[str, FakeValidator]) -> None:
        self.mapping = mapping

    def get_validator(self, code: str) -> FakeValidator | None:
        return self.mapping.get(code)


class FakeCtiConfigRepository:
    """Repository CTI en memoire pour les tests."""

    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = {str(row["code"]): deepcopy(row) for row in rows}

    def list_configs(self) -> list[dict[str, object]]:
        return [deepcopy(row) for row in self.rows.values()]

    def get_by_code(self, code: str) -> dict[str, object] | None:
        row = self.rows.get(code)
        return None if row is None else deepcopy(row)

    def get_key_required_by_code(self, code: str) -> dict[str, object] | None:
        row = self.rows.get(code)
        if row is None or not bool(row.get("is_key_required")):
            return None
        return deepcopy(row)

    def get_key_not_required_by_code(self, code: str) -> dict[str, object] | None:
        row = self.rows.get(code)
        if row is None or bool(row.get("is_key_required")):
            return None
        return deepcopy(row)

    def update_by_code(self, *, code: str, updates: dict[str, object]) -> dict[str, object] | None:
        row = self.rows.get(code)
        if row is None:
            return None
        row.update(updates)
        row["updated_at"] = fixed_now()
        return deepcopy(row)


class CtiConfigServiceTestCase(unittest.TestCase):
    """Couvre les nouvelles regles CTI."""

    def setUp(self) -> None:
        self.repository = FakeCtiConfigRepository([build_cti_row()])
        self.validator = FakeValidator(ValidationResult.ok())
        self.service = CtiConfigService(
            self.repository,
            build_secret_service(),
            FakeCtiValidatorRegistry({"abuseipdb": self.validator}),
            build_validation_settings(),
        )

    def test_get_config_exposes_is_key_required(self) -> None:
        response = self.service.get_config("abuseipdb")

        self.assertTrue(response["is_key_required"])
        self.assertFalse(response["has_api_key"])

    def test_update_rejects_empty_patch_payload(self) -> None:
        payload = CtiConfigUpdateRequestSchema()

        with self.assertRaises(BadRequestError) as context:
            self.service.update_config(code="abuseipdb", payload=payload)

        self.assertEqual(context.exception.code, "invalid_payload")

    def test_update_accepts_label_up_to_150_characters(self) -> None:
        payload = CtiConfigUpdateRequestSchema(label="L" * 150)

        response = self.service.update_config(code="abuseipdb", payload=payload)

        self.assertEqual(response["label"], "L" * 150)

    def test_activate_allows_provider_without_required_api_key(self) -> None:
        repository = FakeCtiConfigRepository(
            [build_cti_row(code="rdap", label="RDAP / WHOIS", is_key_required=False)]
        )
        repository.rows["rdap"]["encrypted_api_key"] = build_secret_service().encrypt_secret(
            "unused-secret"
        )
        repository.rows["rdap"]["api_key_hint"] = "****cret"
        service = CtiConfigService(
            repository,
            build_secret_service(),
            FakeCtiValidatorRegistry({}),
            build_validation_settings(),
        )

        response = service.activate_config("rdap")

        self.assertTrue(response["is_active"])
        self.assertFalse(response["is_key_required"])

    def test_update_refuses_api_key_for_provider_without_required_key(self) -> None:
        repository = FakeCtiConfigRepository(
            [build_cti_row(code="rdap", label="RDAP / WHOIS", is_key_required=False)]
        )
        service = CtiConfigService(
            repository,
            build_secret_service(),
            FakeCtiValidatorRegistry({}),
            build_validation_settings(),
        )
        payload = CtiConfigUpdateRequestSchema(api_key="should-not-be-stored")

        with self.assertRaises(BadRequestError) as context:
            service.update_config(code="rdap", payload=payload)

        self.assertEqual(context.exception.code, "invalid_payload")
        self.assertIn("n'utilise pas de clé API", context.exception.message)

    def test_activate_refuses_provider_when_api_key_is_required(self) -> None:
        with self.assertRaises(BadRequestError) as context:
            self.service.activate_config("abuseipdb")

        self.assertEqual(context.exception.code, "cti_validation_failed")
        self.assertFalse(self.repository.rows["abuseipdb"]["is_active"])
        self.assertEqual(
            self.repository.rows["abuseipdb"]["last_validation_status"],
            "failed",
        )
