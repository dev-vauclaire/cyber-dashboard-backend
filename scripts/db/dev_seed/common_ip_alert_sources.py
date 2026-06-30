"""Seed data for common_ip_alert_sources."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import Connection
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .common_ip_alerts import COMMON_IP_ALERTS
from .context import SeedContext, SeedResult


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert links between common IP alerts and sources."""
    table = context.table("common_ip_alert_sources")
    values = []
    for alert in COMMON_IP_ALERTS:
        alert_id = context.alert_ids[str(alert["key"])]
        for source_index, source_key in enumerate(alert["source_keys"], start=1):
            values.append(
                {
                    "alert_id": alert_id,
                    "source_id": context.source_ids[str(source_key)],
                    "first_seen_at": context.now
                    - timedelta(hours=int(alert["first_hours_ago"]) - source_index),
                    "last_seen_at": context.now
                    - timedelta(hours=int(alert["last_hours_ago"]) + source_index),
                    "hit_count": 2 + source_index * 3,
                }
            )

    statement = pg_insert(table).values(values)
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c.alert_id, table.c.source_id],
            set_={
                "first_seen_at": statement.excluded.first_seen_at,
                "last_seen_at": statement.excluded.last_seen_at,
                "hit_count": statement.excluded.hit_count,
            },
        )
    )
    return SeedResult("common_ip_alert_sources", len(values))
