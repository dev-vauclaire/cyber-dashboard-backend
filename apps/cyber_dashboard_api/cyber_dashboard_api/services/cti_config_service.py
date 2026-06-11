"""Service metier pour les configurations CTI."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cyber_dashboard_api.api.errors import (
    BadRequestError,
    NotFoundError,
    ServiceUnavailableError,
)
from cyber_dashboard_api.api.validation import (
    normalize_optional_text_input,
    validate_secret_update_input,
)
from cyber_dashboard_api.config import ValidationSettings
from cyber_dashboard_api.integrations.common import ValidationResult
from cyber_dashboard_api.integrations.cti.registry import CtiValidatorRegistry
from cyber_dashboard_api.integrations.cti.types import CtiValidationContext
from cyber_dashboard_api.repositories import CtiConfigRepository
from cyber_dashboard_api.services.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)


class CtiConfigService:
    """Encapsule les regles metier des configurations CTI."""

    def __init__(
        self,
        repository: CtiConfigRepository,
        secret_service: SecretService,
        validator_registry: CtiValidatorRegistry,
        validation_settings: ValidationSettings,
    ) -> None:
        self._repository = repository
        self._secret_service = secret_service
        self._validator_registry = validator_registry
        self._validation_settings = validation_settings

    def list_configs(self) -> list[dict[str, Any]]:
        """Retourne toutes les configurations CTI publiques."""
        return [self._to_public_row(row) for row in self._repository.list_configs()]

    def get_config(self, code: str) -> dict[str, Any]:
        """Retourne une configuration CTI publique."""
        row = self._repository.get_by_code(code)
        if row is None:
            raise NotFoundError(
                code="cti_config_not_found",
                message="CTI configuration not found",
            )
        return self._to_public_row(row)

    def update_config(
        self,
        *,
        code: str,
        payload: Any,
    ) -> dict[str, Any]:
        """Met a jour une configuration CTI."""
        if not payload.model_fields_set:
            raise BadRequestError(
                code="invalid_payload",
                message="At least one of 'label' or 'api_key' must be provided",
            )

        updates: dict[str, Any] = {}
        fields_set = payload.model_fields_set
        critical_fields_changed = False

        if "label" in fields_set:
            label = normalize_optional_text_input(
                name="label",
                value=payload.label,
                max_length=150,
            )
            if label is None:
                raise BadRequestError(
                    code="invalid_payload",
                    message="Field 'label' must not be blank",
                )
            updates["label"] = label

        if "api_key" in fields_set:
            if self._repository.get_key_not_required_by_code(code) is not None:
                raise BadRequestError(
                    code="invalid_payload",
                    message="This CTI provider does not use an API key",
                )

            api_key = validate_secret_update_input(
                name="api_key",
                value=payload.api_key,
                delete_endpoint="DELETE /api/cti-config/{code}/api-key",
            )
            updates["encrypted_api_key"] = self._encrypt_secret(api_key)
            updates["api_key_hint"] = self._secret_service.build_secret_hint(api_key)
            critical_fields_changed = True

        if critical_fields_changed:
            updates["is_active"] = False
            self._reset_validation_fields(updates)

        updated_row = self._repository.update_by_code(code=code, updates=updates)
        if updated_row is None:
            raise NotFoundError(
                code="cti_config_not_found",
                message="CTI configuration not found",
            )
        return self._to_public_row(updated_row)

    def activate_config(self, code: str) -> dict[str, Any]:
        """Active une configuration CTI apres validation reelle."""
        row = self._load_row(code)
        validation_result = self._validate_for_activation(row)

        if validation_result.success:
            return self._to_public_row(
                self._persist_validation_success(code=code)
            )

        self._persist_validation_failure(
            code=code,
            message=validation_result.message or "CTI validation failed",
        )
        raise BadRequestError(
            code="cti_validation_failed",
            message=validation_result.message or "CTI validation failed",
        )

    def deactivate_config(self, code: str) -> dict[str, Any]:
        """Desactive une configuration CTI sans effacer sa validation."""
        updated_row = self._repository.update_by_code(
            code=code,
            updates={"is_active": False},
        )
        if updated_row is None:
            raise NotFoundError(
                code="cti_config_not_found",
                message="CTI configuration not found",
            )
        return self._to_public_row(updated_row)

    def delete_api_key(self, code: str) -> dict[str, Any]:
        """Supprime la cle API d'une configuration CTI."""
        updated_row = self._repository.update_by_code(
            code=code,
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
                code="cti_config_not_found",
                message="CTI configuration not found",
            )
        return self._to_public_row(updated_row)

    def _validate_for_activation(self, row: dict[str, Any]) -> ValidationResult:
        code = str(row["code"])
        requires_api_key = self._repository.get_key_required_by_code(code) is not None
        if not requires_api_key:
            return ValidationResult.ok()

        if not self._secret_service.has_secret(row.get("encrypted_api_key")):
            return ValidationResult.fail("This CTI provider requires an API key before activation")

        validator = self._validator_registry.get_validator(code)
        if validator is None:
            return ValidationResult.fail("No validator is configured for this CTI provider")

        decrypted_api_key = self._decrypt_secret(row["encrypted_api_key"])

        return validator.validate(
            CtiValidationContext(
                code=code,
                api_key=decrypted_api_key,
                test_ip=self._validation_settings.test_ip,
            )
        )

    def _persist_validation_success(self, *, code: str) -> dict[str, Any]:
        updated_row = self._repository.update_by_code(
            code=code,
            updates={
                "is_active": True,
                "last_validation_status": "success",
                "last_validation_at": datetime.now(UTC),
                "last_validation_error": None,
            },
        )
        if updated_row is None:
            raise NotFoundError(
                code="cti_config_not_found",
                message="CTI configuration not found",
            )
        return updated_row

    def _persist_validation_failure(
        self,
        *,
        code: str,
        message: str,
    ) -> None:
        updated_row = self._repository.update_by_code(
            code=code,
            updates={
                "is_active": False,
                "last_validation_status": "failed",
                "last_validation_at": datetime.now(UTC),
                "last_validation_error": message,
            },
        )
        if updated_row is None:
            raise NotFoundError(
                code="cti_config_not_found",
                message="CTI configuration not found",
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
                message="Stored CTI secret could not be decrypted",
            ) from exc

    def _load_row(self, code: str) -> dict[str, Any]:
        row = self._repository.get_by_code(code)
        if row is None:
            raise NotFoundError(
                code="cti_config_not_found",
                message="CTI configuration not found",
            )
        return row

    @staticmethod
    def _reset_validation_fields(updates: dict[str, Any]) -> None:
        updates["last_validation_status"] = "not_tested"
        updates["last_validation_at"] = None
        updates["last_validation_error"] = None

    def _to_public_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "code": row["code"],
            "label": row["label"],
            "is_key_required": bool(row["is_key_required"]),
            "is_active": row["is_active"],
            "has_api_key": self._secret_service.has_secret(row.get("encrypted_api_key")),
            "api_key_hint": row["api_key_hint"],
            "last_validation_status": row["last_validation_status"],
            "last_validation_at": row["last_validation_at"],
            "last_validation_error": row["last_validation_error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
