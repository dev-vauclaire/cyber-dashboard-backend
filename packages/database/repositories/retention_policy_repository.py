"""Acces SQL aux politiques de retention."""

from __future__ import annotations

from typing import Any

from packages.database.db import PostgresDatabase


class RetentionPolicyRepository:
    """Gere la lecture et l'ecriture des politiques de retention."""

    _ALLOWED_UPDATE_COLUMNS = {
        "retention_days",
        "is_active",
    }

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def list_policies(self) -> list[dict[str, Any]]:
        """Retourne toutes les politiques de retention."""
        query = """
            SELECT
                id,
                target_table,
                retention_days,
                is_active,
                last_run_at,
                last_deleted_count,
                last_error,
                created_at,
                updated_at
            FROM retention_policies
            ORDER BY target_table ASC
        """
        return self._database.fetch_all(query)

    def get_by_target_table(self, target_table: str) -> dict[str, Any] | None:
        """Retourne une politique de retention par table cible."""
        query = """
            SELECT
                id,
                target_table,
                retention_days,
                is_active,
                last_run_at,
                last_deleted_count,
                last_error,
                created_at,
                updated_at
            FROM retention_policies
            WHERE target_table = %(target_table)s
        """
        return self._database.fetch_one(query, {"target_table": target_table})

    def update_by_target_table(
        self,
        *,
        target_table: str,
        updates: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Met a jour une politique de retention."""
        if not updates:
            return self.get_by_target_table(target_table)

        unknown_columns = set(updates) - self._ALLOWED_UPDATE_COLUMNS
        if unknown_columns:
            raise ValueError(
                f"Unsupported retention policy update columns: {sorted(unknown_columns)}"
            )

        set_clauses = [f"{column} = %({column})s" for column in updates]
        set_clauses.append("updated_at = NOW()")

        query = f"""
            UPDATE retention_policies
            SET {", ".join(set_clauses)}
            WHERE target_table = %(target_table)s
            RETURNING
                id,
                target_table,
                retention_days,
                is_active,
                last_run_at,
                last_deleted_count,
                last_error,
                created_at,
                updated_at
        """
        params = {"target_table": target_table, **updates}

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)
