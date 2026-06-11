"""Lectures SQL relatives aux sources et aux capteurs."""

from __future__ import annotations

from typing import Any

from packages.database.db import PostgresDatabase


class SourceRepository:
    """Expose les lectures de sources et d'inventaire capteurs."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def get_sensor_inventory(self) -> list[dict[str, object]]:
        """Retourne le nombre de sources actives et inactives par type de capteur."""
        query = """
            SELECT
                st.id AS sensor_type_id,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                st.category AS sensor_type_category,
                COUNT(s.id)::INT AS total_sources,
                COUNT(*) FILTER (WHERE s.is_active = TRUE)::INT AS active_sources,
                COUNT(*) FILTER (WHERE s.is_active = FALSE)::INT AS inactive_sources
            FROM sensor_types st
            LEFT JOIN sources s
                ON s.sensor_type_id = st.id
            GROUP BY st.id, st.code, st.label, st.category
            ORDER BY st.code ASC
        """
        return self._database.fetch_all(query)

    def list_sources(self) -> list[dict[str, object]]:
        """Retourne la liste des sources avec leur type de capteur."""
        query = """
            SELECT
                s.id,
                s.name,
                s.color,
                s.is_active,
                s.created_at,
                ogo.site_url,
                st.id AS sensor_type_id,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                st.category AS sensor_type_category
            FROM sources s
            INNER JOIN sensor_types st
                ON st.id = s.sensor_type_id
            LEFT JOIN ogo_sources ogo
                ON ogo.source_id = s.id
            ORDER BY st.code ASC, s.name ASC, s.id ASC
        """
        return self._database.fetch_all(query)

    def rename_source(
        self,
        *,
        source_id: int,
        source_name: str,
    ) -> dict[str, Any] | None:
        """Met a jour le nom d'une source et retourne son etat courant."""
        query = """
            WITH updated_source AS (
                UPDATE sources
                SET name = %(source_name)s
                WHERE id = %(source_id)s
                RETURNING id, name, is_active, created_at, sensor_type_id, color
            )
            SELECT
                us.id,
                us.name,
                us.is_active,
                us.created_at,
                ogo.site_url,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                us.color
            FROM updated_source us
            INNER JOIN sensor_types st
                ON st.id = us.sensor_type_id
            LEFT JOIN ogo_sources ogo
                ON ogo.source_id = us.id
        """
        params = {
            "source_id": source_id,
            "source_name": source_name,
        }

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    def update_source_status(
        self,
        *,
        source_id: int,
        is_active: bool,
    ) -> dict[str, Any] | None:
        """Met a jour le statut d'une source et retourne son etat courant."""
        query = """
            WITH updated_source AS (
                UPDATE sources
                SET is_active = %(is_active)s
                WHERE id = %(source_id)s
                RETURNING id, name, is_active, created_at, sensor_type_id, color
            )
            SELECT
                us.id,
                us.name,
                us.is_active,
                us.created_at,
                ogo.site_url,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                us.color
            FROM updated_source us
            INNER JOIN sensor_types st
                ON st.id = us.sensor_type_id
            LEFT JOIN ogo_sources ogo
                ON ogo.source_id = us.id
        """
        params = {
            "source_id": source_id,
            "is_active": is_active,
        }

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    def update_source_color(
        self,
        *,
        source_id: int,
        color: str,
    ) -> dict[str, Any] | None:
        """Met a jour la couleur d'une source et retourne son etat courant."""
        query = """
            WITH updated_source AS (
                UPDATE sources
                SET color = %(color)s
                WHERE id = %(source_id)s
                RETURNING id, name, is_active, created_at, sensor_type_id, color
            )
            SELECT
                us.id,
                us.name,
                us.is_active,
                us.created_at,
                ogo.site_url,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                us.color
            FROM updated_source us
            INNER JOIN sensor_types st
                ON st.id = us.sensor_type_id
            LEFT JOIN ogo_sources ogo
                ON ogo.source_id = us.id
        """
        params = {
            "source_id": source_id,
            "color": color,
        }

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)
