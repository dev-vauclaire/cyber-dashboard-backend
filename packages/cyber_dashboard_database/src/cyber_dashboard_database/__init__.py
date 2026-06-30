"""Primitives publiques du package de base de donnees partage."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__all__ = [
    "Base",
    "DatabaseSettingsProtocol",
    "PostgresDatabase",
    "build_get_database",
    "metadata",
]

_EXPORTS: dict[str, tuple[str, str]] = {
    "Base": (".models", "Base"),
    "DatabaseSettingsProtocol": (".db", "DatabaseSettingsProtocol"),
    "PostgresDatabase": (".db", "PostgresDatabase"),
    "build_get_database": (".db", "build_get_database"),
    "metadata": (".models", "metadata"),
}


def __getattr__(name: str) -> Any:
    """Charge uniquement la primitive publique demandee."""
    export_target = _EXPORTS.get(name)
    if export_target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attribute_name = export_target
    module = import_module(module_name, __name__)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value


if TYPE_CHECKING:
    from .db import DatabaseSettingsProtocol, PostgresDatabase, build_get_database
    from .models import Base, metadata
