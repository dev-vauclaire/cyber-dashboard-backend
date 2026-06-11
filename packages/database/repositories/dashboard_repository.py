"""Lectures SQL pour la vue d'ensemble du dashboard."""

from __future__ import annotations

from packages.database.db import PostgresDatabase


class DashboardRepository:
    """Expose les lectures necessaires au dashboard overview."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def get_overview_counts(self) -> dict[str, int]:
        """Retourne les compteurs globaux utilises par le dashboard."""
        query = """
            SELECT
                (SELECT COUNT(*)::INT FROM attacks) AS total_attacks,
                (SELECT COUNT(*)::INT FROM common_ip_alerts) AS total_common_ip_alerts,
                (SELECT COUNT(*)::INT FROM sources WHERE is_active = TRUE) AS total_active_sources,
                (SELECT COUNT(*)::INT FROM sources WHERE is_active = FALSE) AS total_inactive_sources
        """
        row = self._database.fetch_one(query)
        if row is None:
            return {
                "total_attacks": 0,
                "total_common_ip_alerts": 0,
                "total_active_sources": 0,
                "total_inactive_sources": 0,
            }
        return row
