"""Façade locale vers la couche DB partagée du monorepo."""

from packages.database.db import PostgresDatabase

__all__ = ["PostgresDatabase"]
