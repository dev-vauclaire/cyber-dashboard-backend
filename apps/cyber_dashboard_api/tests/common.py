"""Helpers partages pour les tests de l'API."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel


def fixed_now() -> datetime:
    """Retourne un horodatage stable pour les assertions."""
    return datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def dump_schema(schema: BaseModel) -> dict[str, object]:
    """Serialise un schema Pydantic comme l'API le ferait en JSON."""
    return schema.model_dump(mode="json", by_alias=True)
