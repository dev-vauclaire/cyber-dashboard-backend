"""Service metier pour les sources et l'inventaire des capteurs."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.repositories import SourceRepository


class SourceService:
    """Encapsule les operations applicatives liees aux sources."""

    def __init__(self, repository: SourceRepository) -> None:
        self._repository = repository

    def get_sensor_inventory(self) -> list[dict[str, Any]]:
        """Retourne l'inventaire agrege des sources par type de capteur."""
        rows = self._repository.get_sensor_inventory()
        return [
            {
                "sensor_type_code": row["sensor_type_code"],
                "sensor_type_label": row["sensor_type_label"],
                "active_count": row["active_sources"],
                "inactive_count": row["inactive_sources"],
            }
            for row in rows
        ]

    def list_sources(self) -> list[dict[str, Any]]:
        """Retourne les sources individuelles au format public de l'API."""
        rows = self._repository.list_sources()
        return [self._to_source_item(row) for row in rows]

    def rename_source(
        self,
        *,
        source_id: int,
        source_name: str,
    ) -> dict[str, Any]:
        """Renomme une source puis retourne son etat public."""
        row = self._repository.rename_source(
            source_id=source_id,
            source_name=source_name,
        )
        return self._require_source_row(row)

    def update_source_status(
        self,
        *,
        source_id: int,
        is_active: bool,
    ) -> dict[str, Any]:
        """Met a jour le statut d'une source puis retourne son etat public."""
        row = self._repository.update_source_status(
            source_id=source_id,
            is_active=is_active,
        )
        return self._require_source_row(row)

    def update_source_color(
        self,
        *,
        source_id: int,
        color: str,
    ) -> dict[str, Any]:
        """Met a jour la couleur d'une source puis retourne son etat public."""
        row = self._repository.update_source_color(
            source_id=source_id,
            color=color,
        )
        return self._require_source_row(row)

    def _require_source_row(self, row: dict[str, Any] | None) -> dict[str, Any]:
        """Garantit qu'une source existe avant de la renvoyer au format public."""
        if row is None:
            raise NotFoundError(
                code="source_not_found",
                message="Source introuvable",
            )
        return self._to_source_item(row)

    @staticmethod
    def _to_source_item(row: dict[str, Any]) -> dict[str, Any]:
        """Projette une ligne SQL source vers le contrat public de l'API."""
        return {
            "source_id": row["id"],
            "source_name": row["name"],
            "domain_name": row.get("domain_name"),
            "is_active": row["is_active"],
            "created_at": row["created_at"],
            "sensor_type_code": row["sensor_type_code"],
            "sensor_type_label": row["sensor_type_label"],
            "color": row["color"],
        }
