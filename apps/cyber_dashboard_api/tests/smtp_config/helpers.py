"""Helpers partages pour les tests SMTP."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cyber_dashboard_api.config import SecretSettings, ValidationSettings
from cyber_dashboard_api.integrations.common import ValidationResult
from cyber_dashboard_api.services import SecretService


def build_valid_fernet_key() -> str:
    """Construit une cle Fernet valide pour les tests."""
    return base64.urlsafe_b64encode(b"3" * 32).decode("utf-8")


def build_secret_service() -> SecretService:
    """Construit le service de secrets utilise dans les tests SMTP."""
    return SecretService(
        SecretSettings(
            secret_key_file=None,
            secret_key=build_valid_fernet_key(),
        )
    )


def build_validation_settings() -> ValidationSettings:
    """Construit les settings minimaux attendus par le service SMTP."""
    return ValidationSettings(
        timeout_seconds=5.0,
        test_ip="8.8.8.8",
        ogo_base_url=None,
        serenicity_base_url=None,
    )


def fixed_now() -> datetime:
    """Horodatage fixe pour les assertions stables."""
    return datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)


def build_smtp_row(
    *,
    smtp_host: str | None = "smtp.example.local",
    smtp_port: int | None = 587,
    smtp_user: str | None = "cyber-dashboard@example.local",
    encrypted_smtp_password: str | None = None,
    smtp_password_hint: str | None = None,
    smtp_from: str | None = "cyber-dashboard@example.local",
    smtp_from_name: str | None = "Cyber Dashboard",
    is_active: bool = False,
    last_validation_status: str | None = "not_tested",
    last_validation_at: datetime | None = None,
    last_validation_error: str | None = None,
) -> dict[str, Any]:
    """Construit une ligne SMTP representative."""
    return {
        "id": 1,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "encrypted_smtp_password": encrypted_smtp_password,
        "smtp_password_hint": smtp_password_hint,
        "smtp_from": smtp_from,
        "smtp_from_name": smtp_from_name,
        "is_active": is_active,
        "last_validation_status": last_validation_status,
        "last_validation_at": last_validation_at,
        "last_validation_error": last_validation_error,
        "created_at": fixed_now(),
        "updated_at": fixed_now(),
    }


def build_public_smtp_response(
    *,
    has_smtp_password: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """Construit une reponse publique conforme au schema API."""
    row = build_smtp_row(**kwargs)
    row.pop("encrypted_smtp_password", None)
    row["has_smtp_password"] = has_smtp_password
    return row


@dataclass
class FakeValidator:
    """Validateur fake qui memorise le contexte recu."""

    result: ValidationResult
    last_context: object | None = None

    def validate(self, context: object) -> ValidationResult:
        self.last_context = context
        return self.result


class FakeSmtpConfigRepository:
    """Repository SMTP en memoire pour les tests."""

    def __init__(self, row: dict[str, Any]) -> None:
        self.row = deepcopy(row)

    def get_or_create_config(self) -> dict[str, Any]:
        return deepcopy(self.row)

    def update_config(self, *, updates: dict[str, Any]) -> dict[str, Any]:
        self.row.update(deepcopy(updates))
        self.row["updated_at"] = fixed_now()
        return deepcopy(self.row)


class FakeSmtpConfigService:
    """Service fake configurable pour les tests de routes SMTP."""

    def __init__(
        self,
        *,
        results: dict[str, Any] | None = None,
        errors: dict[str, Exception] | None = None,
    ) -> None:
        self._results = results or {}
        self._errors = errors or {}
        self.calls: list[dict[str, Any]] = []

    def _dispatch(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(
            {
                "method": method_name,
                "args": args,
                "kwargs": kwargs,
            }
        )
        if method_name in self._errors:
            raise self._errors[method_name]

        if method_name not in self._results:
            raise AssertionError(f"No fake result configured for {method_name}")

        return deepcopy(self._results[method_name])

    def get_config(self) -> dict[str, Any]:
        return self._dispatch("get_config")

    def update_config(self, payload: Any) -> dict[str, Any]:
        return self._dispatch("update_config", payload=payload)

    def activate_config(self) -> dict[str, Any]:
        return self._dispatch("activate_config")

    def test_config(self) -> dict[str, Any]:
        return self._dispatch("test_config")

    def deactivate_config(self) -> dict[str, Any]:
        return self._dispatch("deactivate_config")

    def delete_password(self) -> dict[str, Any]:
        return self._dispatch("delete_password")


def dump_schema(payload: Any) -> dict[str, Any]:
    """Convertit un schema Pydantic en dictionnaire JSON comparable."""
    return payload.model_dump(mode="json")
