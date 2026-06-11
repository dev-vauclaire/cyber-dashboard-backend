"""Lectures SQL pour les statistiques d'attaques."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from packages.database.db import PostgresDatabase


class StatisticsRepository:
    """Expose les lectures statistiques pour les attaques."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def get_attack_total_between(
        self,
        *,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> int:
        """Compte le total d'attaques sur une periode."""
        query = """
            SELECT COUNT(*)::INT AS total
            FROM attacks
            WHERE occurred_at >= %(occurred_from)s
              AND occurred_at <= %(occurred_to)s
        """
        row = self._database.fetch_one(
            query,
            {
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            },
        )
        return 0 if row is None else int(row["total"])

    def get_attack_distribution_by_source(
        self,
        *,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[dict[str, object]]:
        """Retourne la repartition des attaques par source sur une periode."""
        query = """
            SELECT
                s.id AS source_id,
                s.name AS source_name,
                COUNT(a.id)::INT AS attack_count,
                ROUND(
                    COUNT(a.id) * 100.0
                    / NULLIF(SUM(COUNT(a.id)) OVER (), 0),
                    2
                ) AS percentage
            FROM attacks a
            INNER JOIN sources s
                ON s.id = a.source_id
            WHERE a.occurred_at >= %(occurred_from)s
              AND a.occurred_at <= %(occurred_to)s
            GROUP BY s.id, s.name
            ORDER BY attack_count DESC, s.name ASC
        """
        return self._database.fetch_all(
            query,
            {
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            },
        )

    def get_attack_distribution_by_type(
        self,
        *,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[dict[str, object]]:
        """Retourne la repartition des attaques par type sur une periode."""
        query = """
            SELECT
                COALESCE(a.attack_type, 'inconnue') AS attack_type,
                COUNT(a.id)::INT AS attack_count,
                ROUND(
                    COUNT(a.id) * 100.0
                    / NULLIF(SUM(COUNT(a.id)) OVER (), 0),
                    2
                ) AS percentage
            FROM attacks a
            WHERE a.occurred_at >= %(occurred_from)s
              AND a.occurred_at <= %(occurred_to)s
            GROUP BY COALESCE(a.attack_type, 'inconnue')
            ORDER BY attack_count DESC, attack_type ASC
        """
        return self._database.fetch_all(
            query,
            {
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            },
        )

    def get_attack_timeseries_by_source(
        self,
        *,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[dict[str, Any]]:
        """Retourne le nombre d'attaques par source et par jour Europe/Paris."""
        query = """
                SELECT
                s.id AS source_id,
                s.name AS source_name,
                s.color AS source_color,
                s.is_active AS source_is_active_current,
                (
                    date_trunc('day', a.occurred_at AT TIME ZONE 'Europe/Paris')
                    AT TIME ZONE 'Europe/Paris'
                ) AS bucket_start_paris,
                COUNT(a.id)::INT AS bucket_attack_count
                FROM attacks a
                INNER JOIN sources s
                ON s.id = a.source_id
                WHERE a.occurred_at >= %(occurred_from)s
                AND a.occurred_at <= %(occurred_to)s
                GROUP BY
                s.id,
                s.name,
                s.color,
                s.is_active,
                bucket_start_paris
                ORDER BY s.name ASC, s.id ASC, bucket_start_paris ASC;
        """
        return self._database.fetch_all(
            query,
            {
                "occurred_from": occurred_from,
                "occurred_to": occurred_to,
            },
        )
