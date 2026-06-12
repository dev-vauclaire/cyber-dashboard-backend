"""Facade locale vers la couche DB partagee du monorepo."""

from __future__ import annotations

from functools import lru_cache

from common_ip_correlator._runtime import ensure_backend_root_on_path
from common_ip_correlator.config import get_settings

ensure_backend_root_on_path()

from packages.database.db import PostgresDatabase


@lru_cache(maxsize=1)
def get_database() -> PostgresDatabase:
    """Construit une instance partagee d'acces PostgreSQL pour le correlateur."""
    settings = get_settings()
    return PostgresDatabase(settings.database)


__all__ = ["PostgresDatabase", "get_database"]
