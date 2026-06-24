"""Service metier pour la configuration SMTP."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cyber_dashboard_api.api.errors import BadRequestError, ServiceUnavailableError
from cyber_dashboard_api.api.validation import (
    normalize_optional_text_input,
    validate_email_input,
    validate_secret_update_input,
)
from cyber_dashboard_api.config import ValidationSettings
from cyber_dashboard_api.integrations.common import ValidationResult
from cyber_dashboard_api.integrations.smtp.types import SmtpValidationContext
from cyber_dashboard_api.integrations.smtp.validator import SmtpValidator
from cyber_dashboard_api.repositories import SmtpConfigRepository
from cyber_dashboard_api.services.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)


class SmtpConfigService:
    """Encapsule les regles metier de la configuration SMTP."""

    def __init__(
        self,
        repository: SmtpConfigRepository,
        secret_service: SecretService,
        validator: SmtpValidator,
        validation_settings: ValidationSettings,
    ) -> None:
        self._repository = repository
        self._secret_service = secret_service
        self._validator = validator
        self._validation_settings = validation_settings

    def get_config(self) -> dict[str, Any]:
        """Retourne la configuration SMTP publique."""
        return self._to_public_row(self._repository.get_or_create_config())

    def update_config(self, payload: Any) -> dict[str, Any]:
        """Met a jour partiellement la configuration SMTP."""
        current_row = self._repository.get_or_create_config()
        updates: dict[str, Any] = {}
        fields_set = payload.model_fields_set
        critical_fields_changed = False

        if not fields_set:
            raise BadRequestError(
                code="invalid_payload",
                message="Au moins un champ SMTP doit être fourni",
            )

        if "smtp_host" in fields_set:
            normalized_host = self._normalize_required_text_field(
                name="smtp_host",
                value=payload.smtp_host,
                max_length=255,
            )
            updates["smtp_host"] = normalized_host
            critical_fields_changed = critical_fields_changed or (
                normalized_host != current_row["smtp_host"]
            )

        if "smtp_port" in fields_set:
            updates["smtp_port"] = payload.smtp_port
            critical_fields_changed = critical_fields_changed or (
                payload.smtp_port != current_row["smtp_port"]
            )

        if "smtp_user" in fields_set:
            normalized_user = self._normalize_required_text_field(
                name="smtp_user",
                value=payload.smtp_user,
                max_length=255,
            )
            updates["smtp_user"] = normalized_user
            critical_fields_changed = critical_fields_changed or (
                normalized_user != current_row["smtp_user"]
            )

        if "smtp_password" in fields_set:
            smtp_password = validate_secret_update_input(
                name="smtp_password",
                value=payload.smtp_password,
                delete_endpoint="DELETE /api/smtp-config/password",
            )
            updates["encrypted_smtp_password"] = self._encrypt_secret(smtp_password)
            updates["smtp_password_hint"] = self._secret_service.build_secret_hint(
                smtp_password
            )
            critical_fields_changed = True

        if "smtp_from" in fields_set:
            if payload.smtp_from is None:
                normalized_from = None
            else:
                normalized_from = validate_email_input(
                    name="smtp_from",
                    value=payload.smtp_from,
                    max_length=255,
                )
            updates["smtp_from"] = normalized_from
            critical_fields_changed = critical_fields_changed or (
                normalized_from != current_row["smtp_from"]
            )

        if "smtp_from_name" in fields_set:
            normalized_from_name = normalize_optional_text_input(
                name="smtp_from_name",
                value=payload.smtp_from_name,
                max_length=255,
            )
            if normalized_from_name is not None and (
                "\r" in normalized_from_name or "\n" in normalized_from_name
            ):
                raise BadRequestError(
                    code="invalid_payload",
                    message="Le champ 'smtp_from_name' doit tenir sur une seule ligne",
                )
            updates["smtp_from_name"] = normalized_from_name

        if critical_fields_changed:
            updates["is_active"] = False
            self._reset_validation_fields(updates)

        return self._to_public_row(self._repository.update_config(updates=updates))

    def activate_config(self) -> dict[str, Any]:
        """Active la configuration SMTP apres validation reelle."""
        current_row = self._repository.get_or_create_config()
        validation_result = self._validate_for_activation(current_row)

        if validation_result.success:
            return self._to_public_row(self._persist_validation_success())

        self._persist_validation_failure(
            message=validation_result.message or "Réponse SMTP inattendue."
        )
        raise BadRequestError(
            code="smtp_validation_failed",
            message=validation_result.message or "Réponse SMTP inattendue.",
        )

    def test_config(self) -> dict[str, Any]:
        """Valide la configuration SMTP sans changer son statut actif."""
        current_row = self._repository.get_or_create_config()
        validation_result = self._validate_for_activation(current_row)

        if validation_result.success:
            return self._to_public_row(
                self._repository.update_config(
                    updates={
                        "last_validation_status": "success",
                        "last_validation_at": datetime.now(UTC),
                        "last_validation_error": None,
                    }
                )
            )

        self._repository.update_config(
            updates={
                "last_validation_status": "failed",
                "last_validation_at": datetime.now(UTC),
                "last_validation_error": validation_result.message
                or "Réponse SMTP inattendue.",
            }
        )
        raise BadRequestError(
            code="smtp_validation_failed",
            message=validation_result.message or "Réponse SMTP inattendue.",
        )

    def deactivate_config(self) -> dict[str, Any]:
        """Desactive la configuration SMTP sans effacer sa validation."""
        return self._to_public_row(
            self._repository.update_config(updates={"is_active": False})
        )

    def delete_password(self) -> dict[str, Any]:
        """Supprime le mot de passe SMTP et desactive la configuration."""
        return self._to_public_row(
            self._repository.update_config(
                updates={
                    "encrypted_smtp_password": None,
                    "smtp_password_hint": None,
                    "is_active": False,
                    "last_validation_status": "not_tested",
                    "last_validation_at": None,
                    "last_validation_error": None,
                }
            )
        )

    def _validate_for_activation(self, row: dict[str, Any]) -> ValidationResult:
        missing_fields = self._get_missing_required_fields(row)
        if missing_fields:
            return ValidationResult.fail("Configuration SMTP incomplète.")

        decrypted_password = self._decrypt_secret(row["encrypted_smtp_password"])
        return self._validator.validate(
            SmtpValidationContext(
                smtp_host=row["smtp_host"],
                smtp_port=int(row["smtp_port"]),
                smtp_user=row["smtp_user"],
                smtp_password=decrypted_password,
                smtp_from=row["smtp_from"],
                timeout_seconds=self._validation_settings.timeout_seconds,
            )
        )

    def _persist_validation_success(self) -> dict[str, Any]:
        return self._repository.update_config(
            updates={
                "is_active": True,
                "last_validation_status": "success",
                "last_validation_at": datetime.now(UTC),
                "last_validation_error": None,
            }
        )

    def _persist_validation_failure(self, *, message: str) -> None:
        self._repository.update_config(
            updates={
                "is_active": False,
                "last_validation_status": "failed",
                "last_validation_at": datetime.now(UTC),
                "last_validation_error": message,
            }
        )

    def _get_missing_required_fields(self, row: dict[str, Any]) -> list[str]:
        required_fields = {
            "smtp_host": row.get("smtp_host"),
            "smtp_port": row.get("smtp_port"),
            "smtp_user": row.get("smtp_user"),
            "smtp_from": row.get("smtp_from"),
        }
        missing_fields = [
            field_name
            for field_name, value in required_fields.items()
            if value is None or (isinstance(value, str) and not value.strip())
        ]

        if not self._secret_service.has_secret(row.get("encrypted_smtp_password")):
            missing_fields.append("smtp_password")

        return missing_fields

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
                message="Le mot de passe SMTP stocké n'a pas pu être déchiffré",
            ) from exc

    @staticmethod
    def _reset_validation_fields(updates: dict[str, Any]) -> None:
        updates["last_validation_status"] = "not_tested"
        updates["last_validation_at"] = None
        updates["last_validation_error"] = None

    @staticmethod
    def _normalize_required_text_field(
        *,
        name: str,
        value: str | None,
        max_length: int,
    ) -> str | None:
        if value is None:
            return None

        normalized_value = normalize_optional_text_input(
            name=name,
            value=value,
            max_length=max_length,
        )
        if normalized_value is None:
            raise BadRequestError(
                code="invalid_payload",
                message=f"Le champ '{name}' ne doit pas être vide",
            )
        return normalized_value

    def _to_public_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "smtp_host": row["smtp_host"],
            "smtp_port": row["smtp_port"],
            "smtp_user": row["smtp_user"],
            "smtp_from": row["smtp_from"],
            "smtp_from_name": row["smtp_from_name"],
            "is_active": row["is_active"],
            "has_smtp_password": self._secret_service.has_secret(
                row.get("encrypted_smtp_password")
            ),
            "smtp_password_hint": row["smtp_password_hint"],
            "last_validation_status": row["last_validation_status"],
            "last_validation_at": row["last_validation_at"],
            "last_validation_error": row["last_validation_error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
