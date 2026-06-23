"""Lectures SQL relatives aux types de capteurs."""

from __future__ import annotations

from typing import Any

from packages.database.db import PostgresDatabase


class SensorTypeRepository:
    """Expose les lectures partagées sur la table sensor_types."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def list_sensor_types(self) -> list[dict[str, object]]:
        """Retourne tous les types de capteurs triés par identifiant."""
        query = """
            SELECT
                id,
                code,
                label,
                category,
                color
            FROM sensor_types
            ORDER BY id ASC
        """
        return self._database.fetch_all(query)

    def get_supported_sensor_types(self) -> list[dict[str, object]]:
        """Retourne les types de capteurs supportés triés par identifiant."""
        query = """
            SELECT
                code
            FROM sensor_types
        """
        return self._database.fetch_all(query)

    def rename_sensor_type(
        self,
        *,
        sensor_type_id: int,
        label: str,
    ) -> dict[str, Any] | None:
        """Renomme un type de capteur et retourne son etat courant."""
        query = """
            UPDATE sensor_types
            SET label = %(label)s
            WHERE id = %(sensor_type_id)s
            RETURNING
                id,
                code,
                label,
                category,
                color
        """
        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    {"sensor_type_id": sensor_type_id, "label": label},
                )
                row = cursor.fetchone()

        return None if row is None else dict(row)
