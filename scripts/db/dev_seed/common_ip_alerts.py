"""Seed data for common_ip_alerts."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import Connection, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

COMMON_IP_ALERTS = (
    {
        "key": "shared-doc-203",
        "attacker_ip": "203.0.113.10",
        "source_keys": ("ogo-portal", "ogo-extranet", "lurio-main", "detoxio-main"),
        "first_hours_ago": 160,
        "last_hours_ago": 1,
        "status": "open",
    },
    {
        "key": "shared-doc-198",
        "attacker_ip": "198.51.100.23",
        "source_keys": ("ogo-portal", "detoxio-main", "lurio-main"),
        "first_hours_ago": 120,
        "last_hours_ago": 8,
        "status": "open",
    },
    {
        "key": "shared-doc-192",
        "attacker_ip": "192.0.2.77",
        "source_keys": ("lurio-backup", "detoxio-lab"),
        "first_hours_ago": 210,
        "last_hours_ago": 36,
        "status": "investigating",
    },
    {
        "key": "shared-google-dns",
        "attacker_ip": "8.8.8.8",
        "source_keys": ("lurio-backup", "detoxio-main", "ogo-portal"),
        "first_hours_ago": 96,
        "last_hours_ago": 2,
        "status": "open",
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert common IP alerts and store their ids."""
    table = context.table("common_ip_alerts")
    values = [
        {
            "attacker_ip": row["attacker_ip"],
            "first_seen_at": context.now - timedelta(hours=int(row["first_hours_ago"])),
            "last_seen_at": context.now - timedelta(hours=int(row["last_hours_ago"])),
            "distinct_source_count": len(row["source_keys"]),
            "status": row["status"],
        }
        for row in COMMON_IP_ALERTS
    ]
    statement = pg_insert(table).values(values)
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c.attacker_ip],
            set_={
                "first_seen_at": statement.excluded.first_seen_at,
                "last_seen_at": statement.excluded.last_seen_at,
                "distinct_source_count": statement.excluded.distinct_source_count,
                "status": statement.excluded.status,
                "updated_at": func.now(),
            },
        )
    )

    rows = connection.execute(
        select(table.c.id, table.c.attacker_ip).where(
            table.c.attacker_ip.in_([row["attacker_ip"] for row in COMMON_IP_ALERTS])
        )
    ).mappings()
    ids_by_ip = {str(row["attacker_ip"]): int(row["id"]) for row in rows}
    context.alert_ids = {
        row["key"]: ids_by_ip[str(row["attacker_ip"])] for row in COMMON_IP_ALERTS
    }
    return SeedResult("common_ip_alerts", len(values))
