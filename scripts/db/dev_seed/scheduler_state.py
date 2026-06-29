"""Seed data for scheduler_state."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import Connection
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

SCHEDULER_STATES = (
    {
        "source_key": "ogo-portal",
        "inventory_status": "success",
        "inventory_hours_ago": 2,
        "collection_status": "success",
        "collection_minutes_ago": 15,
    },
    {
        "source_key": "ogo-extranet",
        "inventory_status": "success",
        "inventory_hours_ago": 3,
        "collection_status": "success",
        "collection_minutes_ago": 32,
    },
    {
        "source_key": "ogo-archive",
        "inventory_status": "success",
        "inventory_hours_ago": 18,
        "collection_status": "failed",
        "collection_minutes_ago": 50,
        "collection_error": "Development fixture: source disabled upstream",
    },
    {
        "source_key": "lurio-main",
        "inventory_status": "success",
        "inventory_hours_ago": 1,
        "collection_status": "success",
        "collection_minutes_ago": 8,
    },
    {
        "source_key": "lurio-backup",
        "inventory_status": "failed",
        "inventory_hours_ago": 7,
        "inventory_error": "Development fixture: temporary inventory timeout",
        "collection_status": "not_run",
    },
    {
        "source_key": "detoxio-main",
        "inventory_status": "success",
        "inventory_hours_ago": 4,
        "collection_status": "success",
        "collection_minutes_ago": 22,
    },
    {
        "source_key": "detoxio-lab",
        "inventory_status": "failed",
        "inventory_hours_ago": 30,
        "inventory_error": "Development fixture: inactive collector",
        "collection_status": "failed",
        "collection_minutes_ago": 90,
        "collection_error": "Development fixture: inactive collector",
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert scheduler state for each development source."""
    table = context.table("scheduler_state")
    values = [_build_row(context, row) for row in SCHEDULER_STATES]
    statement = pg_insert(table).values(values)
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c.source_id],
            set_={
                "last_inventory_at": statement.excluded.last_inventory_at,
                "last_poll_at": statement.excluded.last_poll_at,
                "last_inventory_status": statement.excluded.last_inventory_status,
                "last_inventory_success_at": (
                    statement.excluded.last_inventory_success_at
                ),
                "last_inventory_error_at": statement.excluded.last_inventory_error_at,
                "last_inventory_error_message": (
                    statement.excluded.last_inventory_error_message
                ),
                "last_collection_status": statement.excluded.last_collection_status,
                "last_collection_success_at": (
                    statement.excluded.last_collection_success_at
                ),
                "last_collection_error_at": statement.excluded.last_collection_error_at,
                "last_collection_error_message": (
                    statement.excluded.last_collection_error_message
                ),
            },
        )
    )
    return SeedResult("scheduler_state", len(values))


def _build_row(context: SeedContext, row: dict[str, object]) -> dict[str, object]:
    source_id = context.source_ids[str(row["source_key"])]
    inventory_at = context.now - timedelta(hours=int(row["inventory_hours_ago"]))
    inventory_status = str(row["inventory_status"])
    collection_status = str(row["collection_status"])

    collection_minutes_ago = row.get("collection_minutes_ago")
    last_poll_at = (
        context.now - timedelta(minutes=int(collection_minutes_ago))
        if collection_minutes_ago is not None
        else None
    )

    return {
        "source_id": source_id,
        "last_inventory_at": inventory_at,
        "last_poll_at": last_poll_at,
        "last_inventory_status": inventory_status,
        "last_inventory_success_at": (
            inventory_at if inventory_status == "success" else None
        ),
        "last_inventory_error_at": (
            inventory_at if inventory_status == "failed" else None
        ),
        "last_inventory_error_message": (
            row.get("inventory_error") if inventory_status == "failed" else None
        ),
        "last_collection_status": collection_status,
        "last_collection_success_at": (
            last_poll_at if collection_status == "success" else None
        ),
        "last_collection_error_at": (
            last_poll_at if collection_status == "failed" else None
        ),
        "last_collection_error_message": (
            row.get("collection_error") if collection_status == "failed" else None
        ),
    }
