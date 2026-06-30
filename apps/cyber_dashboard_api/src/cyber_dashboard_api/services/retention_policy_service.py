"""Service metier pour les politiques de retention."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_api.api.errors import BadRequestError, NotFoundError
from cyber_dashboard_api.api.validation import validate_positive_int_field
from cyber_dashboard_api.repositories import RetentionPolicyRepository

ALLOWED_RETENTION_TARGET_TABLES = {"attacks", "common_ip_alerts"}


class RetentionPolicyService:
    """Encapsule les regles metier des politiques de retention."""

    def __init__(self, repository: RetentionPolicyRepository) -> None:
        self._repository = repository

    def list_policies(self) -> list[dict[str, Any]]:
        """Retourne toutes les politiques de retention."""
        return self._repository.list_policies()

    def get_policy(self, target_table: str) -> dict[str, Any]:
        """Retourne une politique de retention par table cible."""
        normalized_target_table = self._validate_target_table(target_table)
        row = self._repository.get_by_target_table(normalized_target_table)
        if row is None:
            raise NotFoundError(
                code="retention_policy_not_found",
                message="Politique de rétention introuvable",
            )
        return row

    def update_policy(
        self,
        *,
        target_table: str,
        payload: Any,
    ) -> dict[str, Any]:
        """Met a jour une politique de retention."""
        normalized_target_table = self._validate_target_table(target_table)

        updates: dict[str, Any] = {}
        if "retention_days" in payload.model_fields_set:
            if payload.retention_days is None:
                raise BadRequestError(
                    code="invalid_payload",
                    message="Le champ 'retention_days' ne doit pas être nul",
                )
            updates["retention_days"] = validate_positive_int_field(
                name="retention_days",
                value=payload.retention_days,
            )

        if "is_active" in payload.model_fields_set:
            if payload.is_active is None:
                raise BadRequestError(
                    code="invalid_payload",
                    message="Le champ 'is_active' ne doit pas être nul",
                )
            updates["is_active"] = payload.is_active

        row = self._repository.update_by_target_table(
            target_table=normalized_target_table,
            updates=updates,
        )
        if row is None:
            raise NotFoundError(
                code="retention_policy_not_found",
                message="Politique de rétention introuvable",
            )
        return row

    @staticmethod
    def _validate_target_table(target_table: str) -> str:
        normalized_target_table = target_table.strip()
        if normalized_target_table not in ALLOWED_RETENTION_TARGET_TABLES:
            raise BadRequestError(
                code="invalid_target_table",
                message=(
                    "Le champ 'target_table' doit être l'une des valeurs suivantes : "
                    "attacks, common_ip_alerts"
                ),
            )
        return normalized_target_table
