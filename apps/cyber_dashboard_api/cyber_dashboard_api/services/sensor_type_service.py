"""Service metier pour les types de capteurs."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.repositories import SensorTypeRepository


class SensorTypeService:
    """Encapsule les operations applicatives liees aux types de capteurs."""

    def __init__(self, repository: SensorTypeRepository) -> None:
        self._repository = repository

    def rename_sensor_type(
        self,
        *,
        sensor_type_id: int,
        label: str,
    ) -> dict[str, Any]:
        """Renomme un type de capteur puis retourne son etat public."""
        row = self._repository.rename_sensor_type(
            sensor_type_id=sensor_type_id,
            label=label,
        )
        if row is None:
            raise NotFoundError(
                code="sensor_type_not_found",
                message="Type de capteur introuvable",
            )
        return self._to_sensor_type_item(row)

    @staticmethod
    def _to_sensor_type_item(row: dict[str, Any]) -> dict[str, Any]:
        """Projette une ligne SQL sensor_type vers le contrat public de l'API."""
        return {
            "sensor_type_id": row["id"],
            "sensor_type_code": row["code"],
            "sensor_type_label": row["label"],
            "sensor_type_category": row["category"],
            "color": row["color"],
        }
