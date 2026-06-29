"""Seed data for attacks_collector_config."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Connection, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

COLLECTOR_CONFIGS = (
    {
        "key": "ogo-main",
        "name": "dev-ogo-main",
        "collector_type": "ogo",
        "encrypted_email": "dev-encrypted-ogo-user",
        "email_hint": "dev-ogo@example.test",
        "encrypted_api_key": "dev-encrypted-ogo-api-key",
        "api_key_hint": "dev-ogo-key",
        "is_active": True,
        "inventory_requested": False,
        "last_validation_status": "success",
        "last_validation_error": None,
    },
    {
        "key": "serenicity-main",
        "name": "dev-serenicity-main",
        "collector_type": "serenicity",
        "encrypted_email": None,
        "email_hint": None,
        "encrypted_api_key": "dev-encrypted-serenicity-api-key",
        "api_key_hint": "dev-ser-key",
        "is_active": True,
        "inventory_requested": False,
        "last_validation_status": "success",
        "last_validation_error": None,
    },
    {
        "key": "serenicity-disabled",
        "name": "dev-serenicity-off",
        "collector_type": "serenicity",
        "encrypted_email": None,
        "email_hint": None,
        "encrypted_api_key": "dev-disabled-serenicity-api-key",
        "api_key_hint": "dev-off-key",
        "is_active": False,
        "inventory_requested": False,
        "last_validation_status": "failed",
        "last_validation_error": "Disabled development collector",
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert collector configs and store their ids."""
    configs = context.table("attacks_collector_config")
    values = [
        {key: value for key, value in row.items() if key not in {"key"}}
        | {"last_validation_at": context.now}
        for row in COLLECTOR_CONFIGS
    ]

    statement = pg_insert(configs).values(values)
    connection.execute(
        statement.on_conflict_do_update(
            constraint="attacks_collector_config_unique_name_per_type",
            set_={
                "encrypted_email": statement.excluded.encrypted_email,
                "email_hint": statement.excluded.email_hint,
                "encrypted_api_key": statement.excluded.encrypted_api_key,
                "api_key_hint": statement.excluded.api_key_hint,
                "is_active": statement.excluded.is_active,
                "inventory_requested": statement.excluded.inventory_requested,
                "last_validation_status": statement.excluded.last_validation_status,
                "last_validation_at": statement.excluded.last_validation_at,
                "last_validation_error": statement.excluded.last_validation_error,
                "updated_at": func.now(),
            },
        )
    )

    rows = connection.execute(
        select(configs.c.id, configs.c.name, configs.c.collector_type).where(
            configs.c.name.in_([row["name"] for row in COLLECTOR_CONFIGS])
        )
    ).mappings()
    context.collector_config_ids = build_collector_config_ids(rows)
    return SeedResult("attacks_collector_config", len(COLLECTOR_CONFIGS))


def build_collector_config_ids(rows: Any) -> dict[str, int]:
    """Build fixture keys from database rows returned after upsert."""
    ids_by_identity = {
        (_normalize_collector_type(row["collector_type"]), str(row["name"])): int(
            row["id"]
        )
        for row in rows
    }

    ids_by_fixture_key: dict[str, int] = {}
    for fixture in COLLECTOR_CONFIGS:
        identity = (str(fixture["collector_type"]), str(fixture["name"]))
        config_id = ids_by_identity.get(identity)
        if config_id is None:
            raise RuntimeError(
                "Unable to resolve development collector config after upsert: "
                f"{identity}"
            )
        ids_by_fixture_key[str(fixture["key"])] = config_id

    return ids_by_fixture_key


def _normalize_collector_type(value: Any) -> str:
    """Normalize SQLAlchemy enum values and plain strings to DB values."""
    enum_value = getattr(value, "value", None)
    if enum_value is not None:
        return str(enum_value)
    return str(value)
