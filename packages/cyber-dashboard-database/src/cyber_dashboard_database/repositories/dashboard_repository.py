"""Lectures SQL pour la vue d'ensemble du dashboard."""

from __future__ import annotations

from typing import Any

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

    def get_topology(
        self,
        *,
        min_distinct_source_count: int = 3,
        alert_limit: int | None = None,
    ) -> dict[str, list[dict[str, object]]]:
        """Retourne la cartographie collecteurs -> sources -> alertes du dashboard."""
        params: dict[str, Any] = {
            "min_distinct_source_count": min_distinct_source_count,
        }
        alert_limit_clause = ""
        if alert_limit is not None:
            alert_limit_clause = "LIMIT %(alert_limit)s"
            params["alert_limit"] = alert_limit

        collectors_query = """
            SELECT
                id,
                name,
                collector_type,
                is_active,
                inventory_requested,
                last_validation_status,
                last_validation_at,
                last_validation_error
            FROM attacks_collector_config
            WHERE is_active = TRUE
            ORDER BY collector_type ASC, name ASC, id ASC
        """
        sources_query = """
            WITH source_alert_counts AS (
                SELECT
                    source_id,
                    COUNT(alert_id)::INT AS alert_count
                FROM common_ip_alert_sources
                GROUP BY source_id
            )
            SELECT
                s.id AS source_id,
                s.name AS source_name,
                s.color AS source_color,
                s.is_active AS source_is_active,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                config.id AS collector_id,
                config.collector_type,
                COALESCE(source_alert_counts.alert_count, 0)::INT AS alert_count,
                ogo.domain_name,
                ss.external_id,
                scheduler_state.last_inventory_at,
                scheduler_state.last_inventory_status,
                scheduler_state.last_inventory_success_at,
                scheduler_state.last_inventory_error_at,
                scheduler_state.last_inventory_error_message,
                scheduler_state.last_collection_status,
                scheduler_state.last_collection_success_at,
                scheduler_state.last_collection_error_at,
                scheduler_state.last_collection_error_message
            FROM sources AS s
            INNER JOIN sensor_types AS st
                ON st.id = s.sensor_type_id
            LEFT JOIN attacks_collector_config AS config
                ON config.id = s.attacks_collector_config_id
            LEFT JOIN ogo_sources AS ogo
                ON ogo.source_id = s.id
            LEFT JOIN serenicity_sources AS ss
                ON ss.source_id = s.id
            LEFT JOIN scheduler_state
                ON scheduler_state.source_id = s.id
            LEFT JOIN source_alert_counts
                ON source_alert_counts.source_id = s.id
            ORDER BY config.collector_type ASC NULLS LAST, config.name ASC NULLS LAST, st.code ASC, s.name ASC
        """
        alerts_query = f"""
            SELECT
                id AS alert_id,
                attacker_ip::TEXT AS attacker_ip,
                distinct_source_count,
                first_seen_at,
                last_seen_at
            FROM common_ip_alerts
            WHERE distinct_source_count >= %(min_distinct_source_count)s
            ORDER BY distinct_source_count DESC, last_seen_at DESC, attacker_ip ASC
            {alert_limit_clause}
        """
        alert_links_query = f"""
            WITH selected_alerts AS (
                SELECT
                    id
                FROM common_ip_alerts
                WHERE distinct_source_count >= %(min_distinct_source_count)s
                ORDER BY distinct_source_count DESC, last_seen_at DESC, attacker_ip ASC
                {alert_limit_clause}
            )
            SELECT
                cas.alert_id,
                cas.source_id,
                cas.first_seen_at,
                cas.last_seen_at,
                cas.hit_count
            FROM common_ip_alert_sources AS cas
            INNER JOIN selected_alerts
                ON selected_alerts.id = cas.alert_id
            ORDER BY cas.alert_id ASC, cas.last_seen_at DESC, cas.source_id ASC
        """
        return {
            "collectors": self._database.fetch_all(collectors_query),
            "sources": self._database.fetch_all(sources_query),
            "alerts": self._database.fetch_all(alerts_query, params),
            "alert_links": self._database.fetch_all(alert_links_query, params),
        }
