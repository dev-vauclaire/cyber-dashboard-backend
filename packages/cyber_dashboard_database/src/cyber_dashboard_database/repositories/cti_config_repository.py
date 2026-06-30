"""Acces SQL aux configurations CTI."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_database.db import PostgresDatabase


class CtiConfigRepository:
    """Gere la lecture et l'ecriture des configurations CTI."""

    _ALLOWED_UPDATE_COLUMNS = {
        "label",
        "encrypted_api_key",
        "api_key_hint",
        "is_active",
        "last_validation_status",
        "last_validation_at",
        "last_validation_error",
    }

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def list_configs(self) -> list[dict[str, Any]]:
        """Retourne toutes les configurations CTI."""
        query = """
            SELECT
                id,
                code,
                label,
                is_key_required,
                encrypted_api_key,
                api_key_hint,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM cti_config
            ORDER BY id ASC
        """
        return self._database.fetch_all(query)

    def get_by_code(self, code: str) -> dict[str, Any] | None:
        """Retourne une configuration CTI par code."""
        query = """
            SELECT
                id,
                code,
                label,
                is_key_required,
                encrypted_api_key,
                api_key_hint,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM cti_config
            WHERE code = %(code)s
        """
        return self._database.fetch_one(query, {"code": code})

    def get_key_required_by_code(self, code: str) -> dict[str, Any] | None:
        """Retourne une configuration CTI qui exige une cle API."""
        query = """
            SELECT
                id,
                code,
                label,
                is_key_required,
                encrypted_api_key,
                api_key_hint,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM cti_config
            WHERE code = %(code)s
              AND is_key_required = TRUE
        """
        return self._database.fetch_one(query, {"code": code})

    def get_key_not_required_by_code(self, code: str) -> dict[str, Any] | None:
        """Retourne une configuration CTI qui ne requiert pas de cle API."""
        query = """
            SELECT
                id,
                code,
                label,
                is_key_required,
                encrypted_api_key,
                api_key_hint,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM cti_config
            WHERE code = %(code)s
              AND is_key_required = FALSE
        """
        return self._database.fetch_one(query, {"code": code})

    def update_by_code(
        self,
        *,
        code: str,
        updates: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Met a jour une configuration CTI et retourne la ligne finale."""
        if not updates:
            return self.get_by_code(code)

        unknown_columns = set(updates) - self._ALLOWED_UPDATE_COLUMNS
        if unknown_columns:
            raise ValueError(
                f"Unsupported CTI update columns: {sorted(unknown_columns)}"
            )

        set_clauses = [f"{column} = %({column})s" for column in updates]
        set_clauses.append("updated_at = NOW()")

        query = f"""
            UPDATE cti_config
            SET {", ".join(set_clauses)}
            WHERE code = %(code)s
            RETURNING
                id,
                code,
                label,
                is_key_required,
                encrypted_api_key,
                api_key_hint,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
        """
        params = {"code": code, **updates}

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)
