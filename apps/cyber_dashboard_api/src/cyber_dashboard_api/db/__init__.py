"""Facade locale vers la couche DB partagee du monorepo."""

from __future__ import annotations

from functools import lru_cache

from cyber_dashboard_api.config import get_settings
from cyber_dashboard_database.db import PostgresDatabase


@lru_cache(maxsize=1)
def get_database() -> PostgresDatabase:
    """Construit une instance partagee d'acces PostgreSQL pour l'API."""
    settings = get_settings()
    return PostgresDatabase(settings.database)


__all__ = ["PostgresDatabase", "get_database"]
