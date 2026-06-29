"""Seed data for retention_policies."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import Connection, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

RETENTION_POLICIES = (
    {
        "target_table": "attacks",
        "retention_days": 90,
        "is_active": True,
        "last_deleted_count": 12,
        "last_error": None,
    },
    {
        "target_table": "common_ip_alerts",
        "retention_days": 180,
        "is_active": True,
        "last_deleted_count": 2,
        "last_error": None,
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert retention policies with recent run metadata."""
    table = context.table("retention_policies")
    values = [
        row | {"last_run_at": context.now - timedelta(days=1)}
        for row in RETENTION_POLICIES
    ]
    statement = pg_insert(table).values(values)
    connection.execute(
        statement.on_conflict_do_update(
            constraint="retention_policies_target_table_unique",
            set_={
                "retention_days": statement.excluded.retention_days,
                "is_active": statement.excluded.is_active,
                "last_run_at": statement.excluded.last_run_at,
                "last_deleted_count": statement.excluded.last_deleted_count,
                "last_error": statement.excluded.last_error,
                "updated_at": func.now(),
            },
        )
    )
    return SeedResult("retention_policies", len(values))
