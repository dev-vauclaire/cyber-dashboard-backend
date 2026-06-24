"""Ecritures SQL pour le correlateur d'IP communes."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from psycopg import Connection

from cyber_dashboard_database.db import PostgresDatabase


class CommonIpAttackRepository:
    """Expose les operations d'ecriture sur les attaques pour le correlateur."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def claim_pending_batch(self, limit: int) -> list[dict[str, Any]]:
        """Reclame atomiquement un lot d'attaques pending et les marque processing."""
        query = """
            WITH candidate_attacks AS (
                SELECT id
                FROM attacks
                WHERE correlation_status = %(pending_status)s
                ORDER BY occurred_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT %(limit)s
            )
            UPDATE attacks AS claimed_attacks
            SET correlation_status = %(processing_status)s
            FROM candidate_attacks
            WHERE claimed_attacks.id = candidate_attacks.id
            RETURNING
                claimed_attacks.id,
                claimed_attacks.source_id,
                HOST(claimed_attacks.attacker_ip) AS attacker_ip,
                claimed_attacks.occurred_at,
                claimed_attacks.correlation_status AS status
        """
        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    {
                        "pending_status": "pending",
                        "limit": limit,
                        "processing_status": "processing",
                    },
                )
                rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def mark_processed(
        self,
        attack_id: int,
        *,
        connection: Connection | None = None,
    ) -> None:
        """Passe une attaque au statut completed."""
        query = """
            UPDATE attacks
            SET correlation_status = %(completed_status)s
            WHERE id = %(attack_id)s
        """
        with self._cursor(connection) as cursor:
            cursor.execute(
                query,
                {
                    "completed_status": "completed",
                    "attack_id": attack_id,
                },
            )

    def reset_to_pending(self, attack_id: int) -> None:
        """Replace une attaque au statut pending apres echec de traitement."""
        query = """
            UPDATE attacks
            SET correlation_status = %(pending_status)s
            WHERE id = %(attack_id)s
        """
        with self._cursor() as cursor:
            cursor.execute(
                query,
                {
                    "pending_status": "pending",
                    "attack_id": attack_id,
                },
            )

    def requeue_processing_attacks(self) -> int:
        """Replace au demarrage les attaques eventuellement laissees en processing."""
        query = """
            UPDATE attacks
            SET correlation_status = %(pending_status)s
            WHERE correlation_status = %(processing_status)s
        """
        with self._cursor() as cursor:
            cursor.execute(
                query,
                {
                    "pending_status": "pending",
                    "processing_status": "processing",
                },
            )
            return cursor.rowcount

    @contextmanager
    def _cursor(
        self,
        connection: Connection | None = None,
    ) -> Iterator[Any]:
        """Expose un curseur adosse a une connexion existante ou a une transaction locale."""
        if connection is not None:
            with connection.cursor() as cursor:
                yield cursor
            return

        with self._database.transaction() as managed_connection:
            with managed_connection.cursor() as cursor:
                yield cursor
