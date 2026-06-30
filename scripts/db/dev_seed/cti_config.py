"""Seed data for cti_config."""

from __future__ import annotations

from sqlalchemy import Connection, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

CTI_CONFIGS = (
    {
        "code": "abuseipdb",
        "label": "AbuseIPDB",
        "is_key_required": True,
        "is_active": False,
        "last_validation_status": "not_tested",
        "last_validation_error": None,
    },
    {
        "code": "ipdata",
        "label": "IPData",
        "is_key_required": True,
        "is_active": False,
        "last_validation_status": "not_tested",
        "last_validation_error": None,
    },
    {
        "code": "greynoise",
        "label": "GreyNoise",
        "is_key_required": True,
        "is_active": False,
        "last_validation_status": "failed",
        "last_validation_error": "Development fixture: API key not configured",
    },
    {
        "code": "virustotal",
        "label": "VirusTotal",
        "is_key_required": True,
        "is_active": False,
        "last_validation_status": "not_tested",
        "last_validation_error": None,
    },
    {
        "code": "shodan",
        "label": "Shodan",
        "is_key_required": True,
        "is_active": False,
        "last_validation_status": "not_tested",
        "last_validation_error": None,
    },
    {
        "code": "ipinfo",
        "label": "IPinfo",
        "is_key_required": True,
        "is_active": False,
        "last_validation_status": "not_tested",
        "last_validation_error": None,
    },
    {
        "code": "rdap",
        "label": "RDAP / WHOIS",
        "is_key_required": False,
        "is_active": True,
        "last_validation_status": "success",
        "last_validation_error": None,
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert CTI provider configuration rows."""
    table = context.table("cti_config")
    values = [
        {
            **row,
            "encrypted_api_key": None,
            "api_key_hint": None,
            "last_validation_at": context.now,
        }
        for row in CTI_CONFIGS
    ]
    statement = pg_insert(table).values(values)
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c.code],
            set_={
                "label": statement.excluded.label,
                "encrypted_api_key": statement.excluded.encrypted_api_key,
                "api_key_hint": statement.excluded.api_key_hint,
                "is_key_required": statement.excluded.is_key_required,
                "is_active": statement.excluded.is_active,
                "last_validation_status": statement.excluded.last_validation_status,
                "last_validation_at": statement.excluded.last_validation_at,
                "last_validation_error": statement.excluded.last_validation_error,
                "updated_at": func.now(),
            },
        )
    )
    return SeedResult("cti_config", len(values))
