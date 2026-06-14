"""Lectures SQL relatives aux sources et aux capteurs."""

from __future__ import annotations

from typing import Any

from packages.database.db import PostgresDatabase


class SourceRepository:
    """Expose les lectures de sources et les ecritures d'inventaire."""

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
                ogo.domain_name,
                st.id AS sensor_type_id,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                st.category AS sensor_type_category
            FROM sources AS s
            INNER JOIN sensor_types AS st
                ON st.id = s.sensor_type_id
            LEFT JOIN ogo_sources AS ogo
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
                ogo.domain_name,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                us.color
            FROM updated_source AS us
            INNER JOIN sensor_types AS st
                ON st.id = us.sensor_type_id
            LEFT JOIN ogo_sources AS ogo
                ON ogo.source_id = us.id
        """
        return self._execute_single_row_write(
            query,
            {"source_id": source_id, "source_name": source_name},
        )

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
                ogo.domain_name,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                us.color
            FROM updated_source AS us
            INNER JOIN sensor_types AS st
                ON st.id = us.sensor_type_id
            LEFT JOIN ogo_sources AS ogo
                ON ogo.source_id = us.id
        """
        return self._execute_single_row_write(
            query,
            {"source_id": source_id, "is_active": is_active},
        )

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
                ogo.domain_name,
                st.code AS sensor_type_code,
                st.label AS sensor_type_label,
                us.color
            FROM updated_source AS us
            INNER JOIN sensor_types AS st
                ON st.id = us.sensor_type_id
            LEFT JOIN ogo_sources AS ogo
                ON ogo.source_id = us.id
        """
        return self._execute_single_row_write(
            query,
            {"source_id": source_id, "color": color},
        )

    def list_sources_for_inventory(self, *, config_id: int) -> list[dict[str, Any]]:
        """Retourne les sources actuellement rattachees a une configuration."""
        query = """
            SELECT
                s.id AS source_id,
                s.attacks_collector_config_id,
                s.name,
                s.is_active,
                s.color,
                st.code AS sensor_type_code,
                ogo.domain_name,
                ogo.organization_codes,
                ss.external_id,
                ss.latitude,
                ss.longitude
            FROM sources AS s
            INNER JOIN sensor_types AS st
                ON st.id = s.sensor_type_id
            LEFT JOIN ogo_sources AS ogo
                ON ogo.source_id = s.id
            LEFT JOIN serenicity_sources AS ss
                ON ss.source_id = s.id
            WHERE s.attacks_collector_config_id = %(config_id)s
            ORDER BY st.code ASC, s.name ASC, s.id ASC
        """
        return self._database.fetch_all(query, {"config_id": config_id})

    def list_active_ogo_sources_for_collection(self) -> list[dict[str, Any]]:
        """Retourne les sources OGO actives collectables."""
        query = """
            SELECT
                s.id AS source_id,
                s.name AS source_name,
                s.attacks_collector_config_id,
                st.code AS sensor_type_code,
                ogo.domain_name,
                ogo.organization_codes
            FROM sources AS s
            INNER JOIN sensor_types AS st
                ON st.id = s.sensor_type_id
            INNER JOIN ogo_sources AS ogo
                ON ogo.source_id = s.id
            INNER JOIN attacks_collector_config AS config
                ON config.id = s.attacks_collector_config_id
            WHERE s.is_active = TRUE
              AND st.code = 'waf'
              AND config.is_active = TRUE
              AND config.collector_type = 'ogo'
            ORDER BY s.id ASC
        """
        return self._database.fetch_all(query)

    def list_active_serenicity_sources_for_collection(self) -> list[dict[str, Any]]:
        """Retourne les sources Serenicity actives collectables."""
        query = """
            SELECT
                s.id AS source_id,
                s.name AS source_name,
                s.attacks_collector_config_id,
                st.code AS sensor_type_code,
                ss.external_id
            FROM sources AS s
            INNER JOIN sensor_types AS st
                ON st.id = s.sensor_type_id
            INNER JOIN serenicity_sources AS ss
                ON ss.source_id = s.id
            INNER JOIN attacks_collector_config AS config
                ON config.id = s.attacks_collector_config_id
            WHERE s.is_active = TRUE
              AND st.code IN ('detoxio', 'lurio')
              AND config.is_active = TRUE
              AND config.collector_type = 'serenicity'
            ORDER BY s.id ASC
        """
        return self._database.fetch_all(query)

    def upsert_ogo_source(
        self,
        *,
        config_id: int,
        sensor_type_code: str,
        domain_name: str,
        source_name: str,
        is_active: bool,
        default_color: str | None,
        organization_codes: list[str],
    ) -> dict[str, Any]:
        """Cree ou met a jour une source OGO pour une configuration unique."""
        sensor_type_id = self._resolve_sensor_type_id(sensor_type_code)

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                source_row = self._fetch_ogo_source_row_for_update(
                    cursor,
                    domain_name=domain_name,
                )
                if source_row is None:
                    source_id = self._insert_source(
                        cursor,
                        sensor_type_id=sensor_type_id,
                        config_id=config_id,
                        source_name=source_name,
                        is_active=is_active,
                        default_color=default_color,
                    )
                    cursor.execute(
                        """
                        INSERT INTO ogo_sources (
                            source_id,
                            domain_name,
                            organization_codes
                        )
                        VALUES (
                            %(source_id)s,
                            %(domain_name)s,
                            %(organization_codes)s
                        )
                        """,
                        {
                            "source_id": source_id,
                            "domain_name": domain_name,
                            "organization_codes": organization_codes,
                        },
                    )
                # Cas où la source à deja été enregistrée dans la table ogo_sources
                else:
                    source_id = int(source_row["source_id"])
                    # On verifie que le type de capteur et la configuration sont cohérents avec la source existante ( ici on a que WAF pour ogo donc ça sert pas à grand chose mais c'est pour le principe )
                    self._assert_sensor_type_consistency(
                        current_sensor_type_id=source_row["sensor_type_id"],
                        expected_sensor_type_id=sensor_type_id,
                        identity=f"OGO:{domain_name}",
                    )
                    # On vérifie si la source est issue d'une autre configuration, si c'est le cas on lève une exception
                    self._assert_config_consistency(
                        current_config_id=source_row["attacks_collector_config_id"],
                        expected_config_id=config_id,
                        identity=f"OGO:{domain_name}",
                    )
                    # On met à jour la source pour la marquer comme vue dans l'inventaire et on met à jour les codes d'organisation
                    self._mark_source_seen(
                        cursor,
                        source_id=source_id,
                        config_id=config_id,
                        is_active=is_active,
                        default_color=default_color,
                    )
                    cursor.execute(
                        """
                        UPDATE ogo_sources
                        SET organization_codes = %(organization_codes)s
                        WHERE source_id = %(source_id)s
                        """,
                        {
                            "source_id": source_id,
                            "organization_codes": organization_codes,
                        },
                    )

        return {"source_id": source_id}

    def upsert_serenicity_source(
        self,
        *,
        config_id: int,
        sensor_type_code: str,
        external_id: str,
        source_name: str,
        is_active: bool,
        default_color: str | None,
        latitude: float | None,
        longitude: float | None,
    ) -> dict[str, Any]:
        """Cree ou met a jour une source Serenicity pour une configuration unique."""
        sensor_type_id = self._resolve_sensor_type_id(sensor_type_code)

        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                source_row = self._fetch_serenicity_source_row_for_update(
                    cursor,
                    external_id=external_id,
                )
                if source_row is None:
                    source_id = self._insert_source(
                        cursor,
                        sensor_type_id=sensor_type_id,
                        config_id=config_id,
                        source_name=source_name,
                        is_active=is_active,
                        default_color=default_color,
                    )
                    cursor.execute(
                        """
                        INSERT INTO serenicity_sources (
                            source_id,
                            external_id,
                            latitude,
                            longitude
                        )
                        VALUES (
                            %(source_id)s,
                            %(external_id)s,
                            %(latitude)s,
                            %(longitude)s
                        )
                        """,
                        {
                            "source_id": source_id,
                            "external_id": external_id,
                            "latitude": latitude,
                            "longitude": longitude,
                        },
                    )
                else:
                    source_id = int(source_row["source_id"])
                    self._assert_sensor_type_consistency(
                        current_sensor_type_id=source_row["sensor_type_id"],
                        expected_sensor_type_id=sensor_type_id,
                        identity=f"SERENICITY:{external_id}",
                    )
                    self._assert_config_consistency(
                        current_config_id=source_row["attacks_collector_config_id"],
                        expected_config_id=config_id,
                        identity=f"SERENICITY:{external_id}",
                    )
                    self._mark_source_seen(
                        cursor,
                        source_id=source_id,
                        config_id=config_id,
                        is_active=is_active,
                        default_color=default_color,
                    )
                    cursor.execute(
                        """
                        UPDATE serenicity_sources
                        SET
                            latitude = COALESCE(serenicity_sources.latitude, %(latitude)s),
                            longitude = COALESCE(serenicity_sources.longitude, %(longitude)s)
                        WHERE source_id = %(source_id)s
                        """,
                        {
                            "source_id": source_id,
                            "latitude": latitude,
                            "longitude": longitude,
                        },
                    )

        return {"source_id": source_id}

    def deactivate_source(
        self,
        *,
        source_id: int,
        config_id: int,
    ) -> dict[str, Any]:
        """Desactive une source absente du dernier inventaire de sa configuration."""
        query = """
            UPDATE sources
            SET is_active = FALSE
            WHERE id = %(source_id)s
              AND attacks_collector_config_id = %(config_id)s
            RETURNING id AS source_id, is_active
        """
        row = self._execute_single_row_write(
            query,
            {"source_id": source_id, "config_id": config_id},
        )
        if row is None:
            raise RuntimeError("Unable to deactivate source for inventory")
        return row

    def _fetch_ogo_source_row_for_update(
        self,
        cursor: Any,
        *,
        domain_name: str,
    ) -> dict[str, Any] | None:
        cursor.execute(
            """
            SELECT
                s.id AS source_id,
                s.sensor_type_id,
                s.attacks_collector_config_id
            FROM sources AS s
            INNER JOIN ogo_sources AS ogo
                ON ogo.source_id = s.id
            WHERE ogo.domain_name = %(domain_name)s
            FOR UPDATE
            """,
            {"domain_name": domain_name},
        )
        row = cursor.fetchone()
        return None if row is None else dict(row)

    def _fetch_serenicity_source_row_for_update(
        self,
        cursor: Any,
        *,
        external_id: str,
    ) -> dict[str, Any] | None:
        cursor.execute(
            """
            SELECT
                s.id AS source_id,
                s.sensor_type_id,
                s.attacks_collector_config_id
            FROM sources AS s
            INNER JOIN serenicity_sources AS ss
                ON ss.source_id = s.id
            WHERE ss.external_id = %(external_id)s
            FOR UPDATE
            """,
            {"external_id": external_id},
        )
        row = cursor.fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _insert_source(
        cursor: Any,
        *,
        sensor_type_id: int,
        config_id: int,
        source_name: str,
        is_active: bool,
        default_color: str | None,
    ) -> int:
        cursor.execute(
            """
            INSERT INTO sources (
                sensor_type_id,
                attacks_collector_config_id,
                name,
                is_active,
                color
            )
            VALUES (
                %(sensor_type_id)s,
                %(config_id)s,
                %(source_name)s,
                %(is_active)s,
                %(default_color)s
            )
            RETURNING id
            """,
            {
                "sensor_type_id": sensor_type_id,
                "config_id": config_id,
                "source_name": source_name,
                "is_active": is_active,
                "default_color": default_color,
            },
        )
        row = cursor.fetchone()
        if row is None:
            raise RuntimeError("Unable to insert source row")
        return int(row["id"])

    @staticmethod
    def _mark_source_seen(
        cursor: Any,
        *,
        source_id: int,
        config_id: int,
        is_active: bool,
        default_color: str | None,
    ) -> None:
        cursor.execute(
            """
            UPDATE sources
            SET
                attacks_collector_config_id = COALESCE(
                    attacks_collector_config_id,
                    %(config_id)s
                ),
                is_active = %(is_active)s,
                color = CASE
                    WHEN color IS NULL OR BTRIM(color) = ''
                        THEN %(default_color)s
                    ELSE color
                END
            WHERE id = %(source_id)s
            """,
            {
                "source_id": source_id,
                "config_id": config_id,
                "is_active": is_active,
                "default_color": default_color,
            },
        )

    @staticmethod
    def _assert_sensor_type_consistency(
        *,
        current_sensor_type_id: Any,
        expected_sensor_type_id: int,
        identity: str,
    ) -> None:
        if int(current_sensor_type_id) != expected_sensor_type_id:
            raise RuntimeError(
                "Source type mismatch detected during inventory for "
                f"{identity}"
            )

    @staticmethod
    def _assert_config_consistency(
        *,
        current_config_id: Any,
        expected_config_id: int,
        identity: str,
    ) -> None:
        if current_config_id is None:
            return
        if int(current_config_id) != expected_config_id:
            raise RuntimeError(
                "Source already linked to another attacks collector config for "
                f"{identity}"
            )

    def _resolve_sensor_type_id(self, sensor_type_code: str) -> int:
        row = self._database.fetch_one(
            """
            SELECT id
            FROM sensor_types
            WHERE code = %(sensor_type_code)s
            """,
            {"sensor_type_code": sensor_type_code},
        )
        if row is None:
            raise ValueError(f"Unknown sensor type code: {sensor_type_code}")
        return int(row["id"])

    def _execute_single_row_write(
        self,
        query: str,
        params: dict[str, Any],
    ) -> dict[str, Any] | None:
        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()

        return None if row is None else dict(row)
