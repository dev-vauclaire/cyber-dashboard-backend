"""Modèles liés à la table sources."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceSerenicity:
    """Représente une source normalisée dans le format interne du scheduler."""

    sensor_type_code: str
    external_id: str
    name: str
    latitude: float | None
    longitude: float | None
    is_active: bool
    color: str


@dataclass(frozen=True, slots=True)
class SourceOgo:
    """Représente une source ogo normalisée dans le format interne du scheduler."""

    sensor_type_code: str
    domain_name: str
    organization_codes: list[str]
    name: str
    is_active: bool
    color: str
