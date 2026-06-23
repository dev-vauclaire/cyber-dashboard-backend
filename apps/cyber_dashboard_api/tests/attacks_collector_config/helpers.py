"""Helpers partages pour les tests de routes attacks_collector_config."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any


def fixed_now() -> datetime:
    """Horodatage fixe pour des assertions stables."""
    return datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)


def build_config_response(
    *,
    config_id: int = 1,
    name: str = "OGO production",
    collector_type: str = "ogo",
    is_active: bool = False,
    inventory_requested: bool = False,
    has_email: bool = True,
    email_hint: str | None = "****ocal",
    has_api_key: bool = True,
    api_key_hint: str | None = "****1234",
    last_validation_status: str | None = "not_tested",
    last_validation_at: datetime | None = None,
    last_validation_error: str | None = None,
) -> dict[str, Any]:
    """Construit une reponse publique representative."""
    return {
        "id": config_id,
        "name": name,
        "collector_type": collector_type,
        "is_active": is_active,
        "inventory_requested": inventory_requested,
        "has_email": has_email,
        "email_hint": email_hint,
        "has_api_key": has_api_key,
        "api_key_hint": api_key_hint,
        "last_validation_status": last_validation_status,
        "last_validation_at": last_validation_at,
        "last_validation_error": last_validation_error,
        "created_at": fixed_now(),
        "updated_at": fixed_now(),
    }


def build_inventory_response(
    *,
    config_id: int = 1,
) -> dict[str, Any]:
    """Construit une reponse representative de demande d'inventaire."""
    return {
        "attacks_collector_config_id": config_id,
        "inventory_requested": True,
        "updated_at": fixed_now(),
    }


class FakeAttacksCollectorConfigService:
    """Service fake configurable pour les tests de routes."""

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

    def list_configs(self) -> list[dict[str, Any]]:
        return self._dispatch("list_configs")

    def get_config(self, config_id: int) -> dict[str, Any]:
        return self._dispatch("get_config", config_id)

    def create_config(self, payload: Any) -> dict[str, Any]:
        return self._dispatch("create_config", payload)

    def update_config(self, *, config_id: int, payload: Any) -> dict[str, Any]:
        return self._dispatch("update_config", config_id=config_id, payload=payload)

    def delete_config(self, config_id: int) -> None:
        self._dispatch("delete_config", config_id)

    def activate_config(self, config_id: int) -> dict[str, Any]:
        return self._dispatch("activate_config", config_id)

    def deactivate_config(self, config_id: int) -> dict[str, Any]:
        return self._dispatch("deactivate_config", config_id)

    def delete_api_key(self, config_id: int) -> dict[str, Any]:
        return self._dispatch("delete_api_key", config_id)

    def delete_email(self, config_id: int) -> dict[str, Any]:
        return self._dispatch("delete_email", config_id)

    def request_inventory(
        self,
        *,
        config_id: int,
    ) -> dict[str, Any]:
        return self._dispatch(
            "request_inventory",
            config_id=config_id,
        )


def dump_schema(payload: Any) -> dict[str, Any]:
    """Convertit un schema Pydantic en dictionnaire JSON comparable."""
    return payload.model_dump(mode="json")
