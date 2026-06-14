"""Service metier pour les configurations de collecteurs d'attaques."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from psycopg.errors import UniqueViolation

from cyber_dashboard_api.api.errors import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    ServiceUnavailableError,
)
from cyber_dashboard_api.api.validation import (
    normalize_optional_text_input,
    validate_email_input,
    validate_secret_update_input,
)
from cyber_dashboard_api.integrations.attacks_collectors.registry import (
    AttacksCollectorValidatorRegistry,
)
from cyber_dashboard_api.integrations.attacks_collectors.types import (
    AttacksCollectorValidationContext,
)
from cyber_dashboard_api.integrations.common import ValidationResult
from cyber_dashboard_api.repositories import AttacksCollectorConfigRepository
from cyber_dashboard_api.services.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)


class AttacksCollectorConfigService:
    """Encapsule les regles metier des collecteurs d'attaques."""

    def __init__(
        self,
        repository: AttacksCollectorConfigRepository,
        secret_service: SecretService,
        validator_registry: AttacksCollectorValidatorRegistry,
    ) -> None:
        self._repository = repository
        self._secret_service = secret_service
        self._validator_registry = validator_registry

    def list_configs(self) -> list[dict[str, Any]]:
        """Retourne toutes les configurations publiques de collecteurs."""
        return [self._to_public_row(row) for row in self._repository.list_configs()]

    def get_config(self, config_id: int) -> dict[str, Any]:
        """Retourne une configuration publique par identifiant."""
        row = self._repository.get_by_id(config_id)
        if row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )
        return self._to_public_row(row)

    def create_config(self, payload: Any) -> dict[str, Any]:
        """Cree une nouvelle configuration de collecteur."""

        values: dict[str, Any] = {
            "name": self._require_text_field(
                name="name",
                value=payload.name,
                max_length=30,
            ),
            "collector_type": payload.collector_type,
            "is_active": False,
            "last_validation_status": "not_tested",
            "last_validation_at": None,
            "last_validation_error": None,
        }

        if "api_key" in payload.model_fields_set:
            api_key = validate_secret_update_input(
                name="api_key",
                value=payload.api_key,
                delete_endpoint="DELETE /api/attacks-collector-config/{id}/api-key",
            )
            values["encrypted_api_key"] = self._encrypt_secret(api_key)
            values["api_key_hint"] = self._secret_service.build_secret_hint(api_key)

        if "email" in payload.model_fields_set:
            email = validate_email_input(
                name="email",
                value=payload.email,
            )
            values["encrypted_email"] = self._encrypt_secret(email)
            values["email_hint"] = self._secret_service.build_secret_hint(email)

        try:
            row = self._repository.create_config(values=values)
        except UniqueViolation as exc:
            raise ConflictError(
                code="attacks_collector_config_conflict",
                message="A collector configuration with the same type and name already exists",
            ) from exc

        return self._to_public_row(row)

    def update_config(
        self,
        *,
        config_id: int,
        payload: Any,
    ) -> dict[str, Any]:
        """Met a jour une configuration existante."""
        updates: dict[str, Any] = {}
        fields_set = payload.model_fields_set
        critical_fields_changed = False

        if "name" in fields_set:
            updates["name"] = self._require_text_field(
                name="name",
                value=payload.name,
                max_length=30,
            )

        if "collector_type" in fields_set:
            updates["collector_type"] = payload.collector_type
            critical_fields_changed = True

        if "api_key" in fields_set:
            api_key = validate_secret_update_input(
                name="api_key",
                value=payload.api_key,
                delete_endpoint="DELETE /api/attacks-collector-config/{id}/api-key",
            )
            updates["encrypted_api_key"] = self._encrypt_secret(api_key)
            updates["api_key_hint"] = self._secret_service.build_secret_hint(api_key)
            critical_fields_changed = True

        if "email" in fields_set:
            email = validate_email_input(
                name="email",
                value=payload.email,
                delete_endpoint="DELETE /api/attacks-collector-config/{id}/email",
            )
            updates["encrypted_email"] = self._encrypt_secret(email)
            updates["email_hint"] = self._secret_service.build_secret_hint(email)
            critical_fields_changed = True

        # Toute modification d'un secret ou du type de collecteur invalide la
        # validation precedente et force une re-activation explicite.
        if critical_fields_changed:
            updates["is_active"] = False
            self._reset_validation_fields(updates)

        try:
            updated_row = self._repository.update_config(
                config_id=config_id,
                updates=updates,
            )
        except UniqueViolation as exc:
            raise ConflictError(
                code="attacks_collector_config_conflict",
                message="A collector configuration with the same type and name already exists",
            ) from exc

        if updated_row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )

        return self._to_public_row(updated_row)

    def delete_config(self, config_id: int) -> None:
        """Supprime une configuration de collecteur."""
        deleted = self._repository.delete_config(config_id)
        if not deleted:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )

    def activate_config(self, config_id: int) -> dict[str, Any]:
        """Active une configuration de collecteur après validation réelle."""
        row = self._load_row(config_id)
        validation_result = self._validate_for_activation(row)

        if validation_result.success:
            return self._to_public_row(
                self._persist_validation_success(config_id=config_id)
            )

        self._persist_validation_failure(
            config_id=config_id,
            message=validation_result.message
            or "Attacks collector validation failed",
        )
        raise BadRequestError(
            code="attacks_collector_validation_failed",
            message=validation_result.message or "Attacks collector validation failed",
        )

    def deactivate_config(self, config_id: int) -> dict[str, Any]:
        """Desactive une configuration de collecteur sans effacer sa validation."""
        updated_row = self._repository.update_config(
            config_id=config_id,
            updates={"is_active": False},
        )
        if updated_row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )
        return self._to_public_row(updated_row)

    def delete_api_key(self, config_id: int) -> dict[str, Any]:
        """Supprime la cle API et desactive la configuration."""
        updated_row = self._repository.update_config(
            config_id=config_id,
            updates={
                "encrypted_api_key": None,
                "api_key_hint": None,
                "is_active": False,
                "last_validation_status": "not_tested",
                "last_validation_at": None,
                "last_validation_error": None,
            },
        )
        if updated_row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )
        return self._to_public_row(updated_row)

    def delete_email(self, config_id: int) -> dict[str, Any]:
        """Supprime l'email chiffre et desactive la configuration."""
        updated_row = self._repository.update_config(
            config_id=config_id,
            updates={
                "encrypted_email": None,
                "email_hint": None,
                "is_active": False,
                "last_validation_status": "not_tested",
                "last_validation_at": None,
                "last_validation_error": None,
            },
        )
        if updated_row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )
        return self._to_public_row(updated_row)

    def request_inventory(
        self,
        *,
        config_id: int,
    ) -> dict[str, Any]:
        """Demande un inventaire futur sans lancer le scheduler directement."""
        self._load_row(config_id)
        scheduler_row = self._repository.request_inventory(config_id=config_id)
        return {
            "attacks_collector_config_id": scheduler_row["attacks_collector_config_id"],
            "inventory_requested": scheduler_row["inventory_requested"],
            "updated_at": scheduler_row["updated_at"],
        }

    def _validate_for_activation(self, row: dict[str, Any]) -> ValidationResult:
        validator = self._validator_registry.get_validator(str(row["collector_type"]))
        if validator is None:
            return ValidationResult.fail(
                f"{str(row['collector_type']).upper()} validation is unavailable on the API"
            )

        has_api_key = self._secret_service.has_secret(row.get("encrypted_api_key"))
        has_email = self._secret_service.has_secret(row.get("encrypted_email"))
        collector_type = str(row["collector_type"])

        if collector_type == "ogo":
            if not has_api_key or not has_email:
                return ValidationResult.fail(
                    "OGO collector configuration is incomplete and cannot be activated"
                )
        elif collector_type == "serenicity":
            if not has_api_key:
                return ValidationResult.fail(
                    "Serenicity collector configuration is incomplete and cannot be activated"
                )

        decrypted_api_key = (
            self._decrypt_secret(row["encrypted_api_key"]) if has_api_key else None
        )
        decrypted_email = (
            self._decrypt_secret(row["encrypted_email"]) if has_email else None
        )

        return validator.validate(
            AttacksCollectorValidationContext(
                collector_type=collector_type,
                api_key=decrypted_api_key,
                email=decrypted_email,
            )
        )

    def _persist_validation_success(self, *, config_id: int) -> dict[str, Any]:
        updated_row = self._repository.update_config(
            config_id=config_id,
            updates={
                "is_active": True,
                "last_validation_status": "success",
                "last_validation_at": datetime.now(UTC),
                "last_validation_error": None,
            },
        )
        if updated_row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )
        return updated_row

    def _persist_validation_failure(
        self,
        *,
        config_id: int,
        message: str,
    ) -> None:
        updated_row = self._repository.update_config(
            config_id=config_id,
            updates={
                "is_active": False,
                "last_validation_status": "failed",
                "last_validation_at": datetime.now(UTC),
                "last_validation_error": message,
            },
        )
        if updated_row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )

    def _encrypt_secret(self, plain_value: str) -> str:
        try:
            return self._secret_service.encrypt_secret(plain_value)
        except SecretConfigurationError as exc:
            raise ServiceUnavailableError(
                code="secret_key_unavailable",
                message=str(exc),
            ) from exc

    def _decrypt_secret(self, encrypted_value: str) -> str:
        try:
            return self._secret_service.decrypt_secret(encrypted_value)
        except (SecretConfigurationError, SecretDecryptionError) as exc:
            raise ServiceUnavailableError(
                code="secret_key_unavailable",
                message="Stored attacks collector secret could not be decrypted",
            ) from exc

    def _load_row(self, config_id: int) -> dict[str, Any]:
        row = self._repository.get_by_id(config_id)
        if row is None:
            raise NotFoundError(
                code="attacks_collector_config_not_found",
                message="Attacks collector configuration not found",
            )
        return row

    @staticmethod
    def _reset_validation_fields(updates: dict[str, Any]) -> None:
        updates["last_validation_status"] = "not_tested"
        updates["last_validation_at"] = None
        updates["last_validation_error"] = None

    @staticmethod
    def _require_text_field(
        *,
        name: str,
        value: str | None,
        max_length: int,
    ) -> str:
        normalized_value = normalize_optional_text_input(
            name=name,
            value=value,
            max_length=max_length,
        )
        if normalized_value is None:
            raise BadRequestError(
                code="invalid_payload",
                message=f"Field '{name}' must not be blank",
            )
        return normalized_value

    def _to_public_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "collector_type": row["collector_type"],
            "is_active": row["is_active"],
            "inventory_requested": row["inventory_requested"],
            "has_email": self._secret_service.has_secret(row.get("encrypted_email")),
            "email_hint": row.get("email_hint"),
            "has_api_key": self._secret_service.has_secret(row.get("encrypted_api_key")),
            "api_key_hint": row.get("api_key_hint"),
            "last_validation_status": row["last_validation_status"],
            "last_validation_at": row["last_validation_at"],
            "last_validation_error": row["last_validation_error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
