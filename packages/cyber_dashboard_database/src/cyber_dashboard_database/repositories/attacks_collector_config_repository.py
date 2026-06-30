"""Acces SQL aux configurations de collecteurs d'attaques."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_database.db import PostgresDatabase


class AttacksCollectorConfigRepository:
    """Gere les configurations de collecteurs d'attaques."""

    _ALLOWED_UPDATE_COLUMNS = {
        "name",
        "collector_type",
        "encrypted_email",
        "email_hint",
        "encrypted_api_key",
        "api_key_hint",
        "is_active",
        "inventory_requested",
        "last_validation_status",
        "last_validation_at",
        "last_validation_error",
    }

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def list_configs(self) -> list[dict[str, Any]]:
        """Retourne toutes les configurations de collecteurs."""
        query = """
            SELECT
                id,
                name,
                collector_type,
                encrypted_email,
                email_hint,
                encrypted_api_key,
                api_key_hint,
                is_active,
                inventory_requested,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM attacks_collector_config
            ORDER BY collector_type ASC, name ASC, id ASC
        """
        return self._database.fetch_all(query)

    def list_active_inventory_requested_configs(self) -> list[dict[str, Any]]:
        """Retourne les configurations actives en attente d'inventaire."""
        query = """
            SELECT
                id,
                name,
                collector_type,
                encrypted_email,
                email_hint,
                encrypted_api_key,
                api_key_hint,
                is_active,
                inventory_requested,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM attacks_collector_config
            WHERE is_active = TRUE
              AND inventory_requested = TRUE
            ORDER BY collector_type ASC, name ASC, id ASC
        """
        return self._database.fetch_all(query)

    def get_by_id(self, config_id: int) -> dict[str, Any] | None:
        """Retourne une configuration par identifiant."""
        query = """
            SELECT
                id,
                name,
                collector_type,
                encrypted_email,
                email_hint,
                encrypted_api_key,
                api_key_hint,
                is_active,
                inventory_requested,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM attacks_collector_config
            WHERE id = %(config_id)s
        """
        return self._database.fetch_one(query, {"config_id": config_id})

    def create_config(
        self,
        *,
        values: dict[str, Any],
    ) -> dict[str, Any]:
        """Cree une configuration de collecteur."""
        columns = ", ".join(values.keys())
        placeholders = ", ".join(f"%({column})s" for column in values)

        query = f"""
            INSERT INTO attacks_collector_config ({columns})
            VALUES ({placeholders})
            RETURNING
                id,
                name,
                collector_type,
                encrypted_email,
                email_hint,
                encrypted_api_key,
                api_key_hint,
                is_active,
                inventory_requested,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
        """

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, values)
                row = cursor.fetchone()

        if row is None:
            raise RuntimeError("Unable to create attacks_collector_config row")

        return dict(row)

    def update_config(
        self,
        *,
        config_id: int,
        updates: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Met a jour une configuration de collecteur."""
        if not updates:
            return self.get_by_id(config_id)

        unknown_columns = set(updates) - self._ALLOWED_UPDATE_COLUMNS
        if unknown_columns:
            raise ValueError(
                f"Unsupported attacks collector update columns: {sorted(unknown_columns)}"
            )

        set_clauses = [f"{column} = %({column})s" for column in updates]
        set_clauses.append("updated_at = NOW()")

        query = f"""
            UPDATE attacks_collector_config
            SET {", ".join(set_clauses)}
            WHERE id = %(config_id)s
            RETURNING
                id,
                name,
                collector_type,
                encrypted_api_key,
                api_key_hint,
                encrypted_email,
                email_hint,
                is_active,
                inventory_requested,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
        """
        params = {"config_id": config_id, **updates}

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    def delete_config(self, config_id: int) -> bool:
        """Supprime une configuration de collecteur."""
        query = """
            DELETE FROM attacks_collector_config
            WHERE id = %(config_id)s
        """
        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, {"config_id": config_id})
                return cursor.rowcount > 0

    def request_inventory(
        self,
        *,
        config_id: int,
    ) -> dict[str, Any]:
        """Marque une configuration pour un futur inventaire par le scheduler."""
        query = """
            UPDATE attacks_collector_config
            SET inventory_requested = TRUE,
                updated_at = NOW()
            WHERE id = %(config_id)s
            RETURNING
                id AS attacks_collector_config_id,
                inventory_requested,
                updated_at
        """
        params = {"config_id": config_id}

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            raise RuntimeError("Unable to update attacks_collector_config row")

        return dict(row)

    def clear_inventory_request(self, *, config_id: int) -> dict[str, Any] | None:
        """Marque une configuration comme inventoriée avec succès."""
        return self.update_config(
            config_id=config_id,
            updates={"inventory_requested": False},
        )
