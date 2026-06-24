"""Modeles internes de filtres simples pour les endpoints read-only."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class TimeRange:
    """Represente une fenetre temporelle de filtrage."""

    start_at: datetime
    end_at: datetime


@dataclass(frozen=True, slots=True)
class AttackFilters:
    """Represente les filtres optionnels de la liste des attaques."""

    source_id: int | None = None
    sensor_type_code: str | None = None
    attack_type: str | None = None
    start_at: datetime | None = None
    end_at: datetime | None = None
