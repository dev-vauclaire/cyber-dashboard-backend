"""Façade locale vers la couche DB partagée du monorepo."""

from cyber_dashboard_database.db import PostgresDatabase

__all__ = ["PostgresDatabase"]
