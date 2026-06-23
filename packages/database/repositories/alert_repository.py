"""Lectures SQL pour les alertes d'IP communes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from packages.database.db import PostgresDatabase


class AlertRepository:
    """Expose les lectures des alertes globales et de leur detail."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def _build_filter_clause(
        self,
        *,
        source_ids: list[int] | None = None,
        last_seen_from: datetime | None = None,
        last_seen_to: datetime | None = None,
        min_distinct_source_count: int | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Construit la clause WHERE selon les filtres fournis."""
        clauses: list[str] = []
        params: dict[str, Any] = {}

        if source_ids:
            clauses.append("""
                EXISTS (
                    SELECT 1
                    FROM common_ip_alert_sources cas
                    WHERE cas.alert_id = a.id
                      AND cas.source_id = ANY(%(source_ids)s::INT[])
                )
                """)
            params["source_ids"] = source_ids

        if last_seen_from is not None:
            clauses.append("a.last_seen_at >= %(last_seen_from)s")
            params["last_seen_from"] = last_seen_from

        if last_seen_to is not None:
            clauses.append("a.last_seen_at <= %(last_seen_to)s")
            params["last_seen_to"] = last_seen_to

        if min_distinct_source_count is not None:
            clauses.append("a.distinct_source_count >= %(min_distinct_source_count)s")
            params["min_distinct_source_count"] = min_distinct_source_count

        if not clauses:
            return "", params

        return "WHERE " + " AND ".join(clauses), params

    def list_common_ip_alerts(
        self,
        *,
        limit: int,
        offset: int,
        source_ids: list[int] | None = None,
        last_seen_from: datetime | None = None,
        last_seen_to: datetime | None = None,
        min_distinct_source_count: int | None = None,
    ) -> list[dict[str, Any]]:
        """Retourne une liste paginee d'alertes IP communes."""
        where_clause, params = self._build_filter_clause(
            source_ids=source_ids,
            last_seen_from=last_seen_from,
            last_seen_to=last_seen_to,
            min_distinct_source_count=min_distinct_source_count,
        )

        query = f"""
            SELECT
                a.id,
                a.attacker_ip::TEXT AS attacker_ip,
                a.distinct_source_count,
                a.first_seen_at,
                a.last_seen_at
            FROM common_ip_alerts a
            {where_clause}
            ORDER BY a.distinct_source_count DESC, a.last_seen_at DESC, a.attacker_ip ASC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset
        return self._database.fetch_all(query, params)

    def count_common_ip_alerts(
        self,
        *,
        source_ids: list[int] | None = None,
        last_seen_from: datetime | None = None,
        last_seen_to: datetime | None = None,
        min_distinct_source_count: int | None = None,
    ) -> int:
        """Compte les alertes IP communes selon les filtres fournis."""
        where_clause, params = self._build_filter_clause(
            source_ids=source_ids,
            last_seen_from=last_seen_from,
            last_seen_to=last_seen_to,
            min_distinct_source_count=min_distinct_source_count,
        )

        query = f"""
            SELECT COUNT(*)::INT AS total
            FROM common_ip_alerts a
            {where_clause}
        """
        row = self._database.fetch_one(query, params)
        return 0 if row is None else int(row["total"])

    def get_alert_detail_by_alert_id(
        self,
        alert_id: int,
    ) -> list[dict[str, object]]:
        """Retourne le detail d'une alerte par source associee."""
        query = """
            SELECT
                a.attacker_ip::TEXT AS attacker_ip,
                s.id AS source_id,
                s.name AS source_name,
                st.code AS sensor_type_code,
                config.collector_type,
                ogo.domain_name,
                ss.external_id,
                cas.first_seen_at,
                cas.last_seen_at,
                cas.hit_count
            FROM common_ip_alerts a
            INNER JOIN common_ip_alert_sources cas
                ON cas.alert_id = a.id
            INNER JOIN sources s
                ON s.id = cas.source_id
            INNER JOIN sensor_types st
                ON st.id = s.sensor_type_id
            LEFT JOIN attacks_collector_config config
                ON config.id = s.attacks_collector_config_id
            LEFT JOIN ogo_sources ogo
                ON ogo.source_id = s.id
            LEFT JOIN serenicity_sources ss
                ON ss.source_id = s.id
            WHERE a.id = %(alert_id)s
            ORDER BY cas.last_seen_at DESC, s.name ASC
        """
        return self._database.fetch_all(query, {"alert_id": alert_id})
