"""Seed data for sensor_types."""

from __future__ import annotations

from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

SENSOR_TYPES = (
    {
        "code": "lurio",
        "label": "Lurio Honeypot",
        "category": "leurre",
        "color": "#4A5D4E",
    },
    {
        "code": "detoxio",
        "label": "Detoxio",
        "category": "detection",
        "color": "#A8C2C0",
    },
    {
        "code": "waf",
        "label": "Web Application Firewall",
        "category": "protection",
        "color": "#E5DCD3",
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert supported sensor types and store their ids."""
    sensor_types = context.table("sensor_types")

    statement = pg_insert(sensor_types).values(list(SENSOR_TYPES))
    update_columns = {
        "label": statement.excluded.label,
        "category": statement.excluded.category,
        "color": statement.excluded.color,
    }
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[sensor_types.c.code],
            set_=update_columns,
        )
    )

    rows = connection.execute(
        select(sensor_types.c.id, sensor_types.c.code).where(
            sensor_types.c.code.in_([row["code"] for row in SENSOR_TYPES])
        )
    ).mappings()
    context.sensor_type_ids = {str(row["code"]): int(row["id"]) for row in rows}
    return SeedResult("sensor_types", len(SENSOR_TYPES))
