"""Lectures SQL relatives aux types de capteurs."""

from __future__ import annotations

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