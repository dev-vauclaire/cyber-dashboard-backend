"""Lectures SQL utilitaires pour reconstruire l'etat du correlateur."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_database.db import PostgresDatabase


class CommonIpStateRepository:
    """Charge les observations deja traitees pour amorcer le registre memoire."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def load_seen_ips(self) -> list[dict[str, Any]]:
        """Retourne les observations agregees par IP et par source."""
        query = """
            SELECT
                HOST(attacker_ip) AS attacker_ip,
                source_id,
                MIN(occurred_at) AS first_seen_at,
                MAX(occurred_at) AS last_seen_at,
                COUNT(*) AS hit_count
            FROM attacks
            WHERE correlation_status = %(completed_status)s
            GROUP BY attacker_ip, source_id
            ORDER BY attacker_ip, source_id
        """
        return self._database.fetch_all(
            query,
            {"completed_status": "completed"},
        )
