"""Acces SQL a la configuration SMTP."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_database.db import PostgresDatabase


class SmtpConfigRepository:
    """Gere la configuration SMTP singleton."""

    _ALLOWED_UPDATE_COLUMNS = {
        "smtp_host",
        "smtp_port",
        "smtp_user",
        "encrypted_smtp_password",
        "smtp_password_hint",
        "smtp_from",
        "smtp_from_name",
        "is_active",
        "last_validation_status",
        "last_validation_at",
        "last_validation_error",
    }

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def get_or_create_config(self) -> dict[str, Any]:
        """Retourne la configuration SMTP singleton et la cree si besoin."""
        query = """
            SELECT
                id,
                smtp_host,
                smtp_port,
                smtp_user,
                encrypted_smtp_password,
                smtp_password_hint,
                smtp_from,
                smtp_from_name,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
            FROM smtp_config
            WHERE id = 1
        """
        row = self._database.fetch_one(query)
        if row is not None:
            return row

        insert_query = """
            INSERT INTO smtp_config (id, is_active, last_validation_status)
            VALUES (1, FALSE, 'not_tested')
            ON CONFLICT (id) DO NOTHING
            RETURNING
                id,
                smtp_host,
                smtp_port,
                smtp_user,
                encrypted_smtp_password,
                smtp_password_hint,
                smtp_from,
                smtp_from_name,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
        """

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(insert_query)
                created_row = cursor.fetchone()

        if created_row is not None:
            return dict(created_row)

        fallback_row = self._database.fetch_one(query)
        if fallback_row is None:
            raise RuntimeError("Unable to initialize smtp_config singleton row")
        return fallback_row

    def update_config(
        self,
        *,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        """Met a jour la configuration SMTP singleton."""
        if not updates:
            return self.get_or_create_config()

        unknown_columns = set(updates) - self._ALLOWED_UPDATE_COLUMNS
        if unknown_columns:
            raise ValueError(
                f"Unsupported SMTP update columns: {sorted(unknown_columns)}"
            )

        self.get_or_create_config()

        set_clauses = [f"{column} = %({column})s" for column in updates]
        set_clauses.append("updated_at = NOW()")

        query = f"""
            UPDATE smtp_config
            SET {", ".join(set_clauses)}
            WHERE id = 1
            RETURNING
                id,
                smtp_host,
                smtp_port,
                smtp_user,
                encrypted_smtp_password,
                smtp_password_hint,
                smtp_from,
                smtp_from_name,
                is_active,
                last_validation_status,
                last_validation_at,
                last_validation_error,
                created_at,
                updated_at
        """

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, updates)
                row = cursor.fetchone()

        if row is None:
            raise RuntimeError("smtp_config singleton row is missing after update")

        return dict(row)
