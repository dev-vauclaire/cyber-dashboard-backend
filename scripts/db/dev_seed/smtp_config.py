"""Seed data for smtp_config."""

from __future__ import annotations

from sqlalchemy import Connection, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

SMTP_CONFIG = {
    "id": 1,
    "smtp_host": "mailhog",
    "smtp_port": 1025,
    "smtp_user": None,
    "encrypted_smtp_password": None,
    "smtp_password_hint": None,
    "smtp_from": "cyber-dashboard-dev@example.test",
    "smtp_from_name": "Cyber Dashboard Dev",
    "is_active": False,
    "last_validation_status": "not_tested",
    "last_validation_error": None,
}


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert the singleton SMTP configuration."""
    table = context.table("smtp_config")
    statement = pg_insert(table).values(
        SMTP_CONFIG | {"last_validation_at": context.now}
    )
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c.id],
            set_={
                "smtp_host": statement.excluded.smtp_host,
                "smtp_port": statement.excluded.smtp_port,
                "smtp_user": statement.excluded.smtp_user,
                "encrypted_smtp_password": statement.excluded.encrypted_smtp_password,
                "smtp_password_hint": statement.excluded.smtp_password_hint,
                "smtp_from": statement.excluded.smtp_from,
                "smtp_from_name": statement.excluded.smtp_from_name,
                "is_active": statement.excluded.is_active,
                "last_validation_status": statement.excluded.last_validation_status,
                "last_validation_at": statement.excluded.last_validation_at,
                "last_validation_error": statement.excluded.last_validation_error,
                "updated_at": func.now(),
            },
        )
    )
    return SeedResult("smtp_config", 1)
