"""Ecritures SQL relatives a scheduler_state."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cyber_dashboard_database.db import PostgresDatabase


class SchedulerStateRepository:
    """Gere l'etat d'inventaire et de collecte du scheduler par source."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def get_by_source_id(self, source_id: int) -> dict[str, Any] | None:
        """Retourne l'etat du scheduler pour une source."""
        query = """
            SELECT
                source_id,
                last_inventory_at,
                last_poll_at,
                last_inventory_status,
                last_inventory_success_at,
                last_inventory_error_at,
                last_inventory_error_message,
                last_collection_status,
                last_collection_success_at,
                last_collection_error_at,
                last_collection_error_message
            FROM scheduler_state
            WHERE source_id = %(source_id)s
        """
        return self._database.fetch_one(query, {"source_id": source_id})

    def mark_inventory_success(
        self,
        *,
        source_id: int,
        inventory_timestamp: datetime,
    ) -> dict[str, Any]:
        """Enregistre un succes d'inventaire pour une source."""
        query = """
            INSERT INTO scheduler_state (
                source_id,
                last_inventory_at,
                last_inventory_status,
                last_inventory_success_at,
                last_inventory_error_at,
                last_inventory_error_message
            )
            VALUES (
                %(source_id)s,
                %(inventory_timestamp)s,
                'success',
                %(inventory_timestamp)s,
                NULL,
                NULL
            )
            ON CONFLICT (source_id)
            DO UPDATE SET
                last_inventory_at = EXCLUDED.last_inventory_at,
                last_inventory_status = 'success',
                last_inventory_success_at = EXCLUDED.last_inventory_success_at,
                last_inventory_error_at = NULL,
                last_inventory_error_message = NULL
            RETURNING
                source_id,
                last_inventory_at,
                last_poll_at,
                last_inventory_status,
                last_inventory_success_at,
                last_inventory_error_at,
                last_inventory_error_message,
                last_collection_status,
                last_collection_success_at,
                last_collection_error_at,
                last_collection_error_message
        """
        params = {
            "source_id": source_id,
            "inventory_timestamp": inventory_timestamp,
        }
        return self._execute_write(query, params)

    def mark_inventory_failure(
        self,
        *,
        source_id: int,
        inventory_timestamp: datetime,
        error_message: str,
    ) -> dict[str, Any]:
        """Enregistre un echec d'inventaire pour une source."""
        query = """
            INSERT INTO scheduler_state (
                source_id,
                last_inventory_at,
                last_inventory_status,
                last_inventory_success_at,
                last_inventory_error_at,
                last_inventory_error_message
            )
            VALUES (
                %(source_id)s,
                %(inventory_timestamp)s,
                'failed',
                NULL,
                %(inventory_timestamp)s,
                %(error_message)s
            )
            ON CONFLICT (source_id)
            DO UPDATE SET
                last_inventory_at = EXCLUDED.last_inventory_at,
                last_inventory_status = 'failed',
                last_inventory_error_at = EXCLUDED.last_inventory_error_at,
                last_inventory_error_message = EXCLUDED.last_inventory_error_message
            RETURNING
                source_id,
                last_inventory_at,
                last_poll_at,
                last_inventory_status,
                last_inventory_success_at,
                last_inventory_error_at,
                last_inventory_error_message,
                last_collection_status,
                last_collection_success_at,
                last_collection_error_at,
                last_collection_error_message
        """
        params = {
            "source_id": source_id,
            "inventory_timestamp": inventory_timestamp,
            "error_message": error_message,
        }
        return self._execute_write(query, params)

    def mark_collection_success(
        self,
        *,
        source_id: int,
        last_poll_at: datetime,
        success_timestamp: datetime,
    ) -> dict[str, Any]:
        """Enregistre un succes de collecte pour une source."""
        query = """
            INSERT INTO scheduler_state (
                source_id,
                last_poll_at,
                last_collection_status,
                last_collection_success_at,
                last_collection_error_at,
                last_collection_error_message
            )
            VALUES (
                %(source_id)s,
                %(last_poll_at)s,
                'success',
                %(success_timestamp)s,
                NULL,
                NULL
            )
            ON CONFLICT (source_id)
            DO UPDATE SET
                last_poll_at = EXCLUDED.last_poll_at,
                last_collection_status = 'success',
                last_collection_success_at = EXCLUDED.last_collection_success_at,
                last_collection_error_at = NULL,
                last_collection_error_message = NULL
            RETURNING
                source_id,
                last_inventory_at,
                last_poll_at,
                last_inventory_status,
                last_inventory_success_at,
                last_inventory_error_at,
                last_inventory_error_message,
                last_collection_status,
                last_collection_success_at,
                last_collection_error_at,
                last_collection_error_message
        """
        return self._execute_write(
            query,
            {
                "source_id": source_id,
                "last_poll_at": last_poll_at,
                "success_timestamp": success_timestamp,
            },
        )

    def mark_collection_failure(
        self,
        *,
        source_id: int,
        error_timestamp: datetime,
        error_message: str,
        last_poll_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Enregistre un echec de collecte pour une source."""
        query = """
            INSERT INTO scheduler_state (
                source_id,
                last_poll_at,
                last_collection_status,
                last_collection_success_at,
                last_collection_error_at,
                last_collection_error_message
            )
            VALUES (
                %(source_id)s,
                %(last_poll_at)s,
                'failed',
                NULL,
                %(error_timestamp)s,
                %(error_message)s
            )
            ON CONFLICT (source_id)
            DO UPDATE SET
                last_poll_at = COALESCE(EXCLUDED.last_poll_at, scheduler_state.last_poll_at),
                last_collection_status = 'failed',
                last_collection_error_at = EXCLUDED.last_collection_error_at,
                last_collection_error_message = EXCLUDED.last_collection_error_message
            RETURNING
                source_id,
                last_inventory_at,
                last_poll_at,
                last_inventory_status,
                last_inventory_success_at,
                last_inventory_error_at,
                last_inventory_error_message,
                last_collection_status,
                last_collection_success_at,
                last_collection_error_at,
                last_collection_error_message
        """
        return self._execute_write(
            query,
            {
                "source_id": source_id,
                "last_poll_at": last_poll_at,
                "error_timestamp": error_timestamp,
                "error_message": error_message,
            },
        )

    def _execute_write(
        self,
        query: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            raise RuntimeError("Unable to write scheduler_state row")

        return dict(row)
