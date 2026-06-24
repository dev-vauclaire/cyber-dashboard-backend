"""Helpers de construction de la couche DB."""

from __future__ import annotations

from functools import lru_cache
from typing import Callable

from .postgres import DatabaseSettingsProtocol, PostgresDatabase


def build_get_database(
    settings_factory: Callable[[], DatabaseSettingsProtocol],
) -> Callable[[], PostgresDatabase]:
    """Construit un provider memoise de PostgresDatabase pour une application."""

    @lru_cache(maxsize=1)
    def _get_database() -> PostgresDatabase:
        settings = settings_factory()
        return PostgresDatabase(settings)

    return _get_database
