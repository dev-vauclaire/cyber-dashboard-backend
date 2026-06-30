"""Seed data for sources, ogo_sources and serenicity_sources."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Connection, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

SOURCES = (
    {
        "key": "ogo-portal",
        "kind": "ogo",
        "sensor_type_code": "waf",
        "collector_config_key": "ogo-main",
        "name": "Portail patient WAF",
        "is_active": True,
        "color": "#2563EB",
        "domain_name": "portal.ch-vauclaire.test",
        "organization_codes": ["CHV", "DMZ"],
    },
    {
        "key": "ogo-extranet",
        "kind": "ogo",
        "sensor_type_code": "waf",
        "collector_config_key": "ogo-main",
        "name": "Extranet RH WAF",
        "is_active": True,
        "color": "#0F766E",
        "domain_name": "rh.ch-vauclaire.test",
        "organization_codes": ["CHV", "HR"],
    },
    {
        "key": "ogo-archive",
        "kind": "ogo",
        "sensor_type_code": "waf",
        "collector_config_key": "ogo-main",
        "name": "Archive documentaire WAF",
        "is_active": False,
        "color": "#64748B",
        "domain_name": "archives.ch-vauclaire.test",
        "organization_codes": ["CHV", "ARCH"],
    },
    {
        "key": "lurio-main",
        "kind": "serenicity",
        "sensor_type_code": "lurio",
        "collector_config_key": "serenicity-main",
        "name": "Lurio Paris Est",
        "is_active": True,
        "color": "#7C3AED",
        "external_id": "910001",
        "latitude": 48.8566,
        "longitude": 2.3522,
    },
    {
        "key": "lurio-backup",
        "kind": "serenicity",
        "sensor_type_code": "lurio",
        "collector_config_key": "serenicity-main",
        "name": "Lurio Secours",
        "is_active": False,
        "color": "#A855F7",
        "external_id": "910002",
        "latitude": 48.8014,
        "longitude": 2.1301,
    },
    {
        "key": "detoxio-main",
        "kind": "serenicity",
        "sensor_type_code": "detoxio",
        "collector_config_key": "serenicity-main",
        "name": "Detoxio Perimetre",
        "is_active": True,
        "color": "#DC2626",
        "external_id": "920001",
        "latitude": 45.764,
        "longitude": 4.8357,
    },
    {
        "key": "detoxio-lab",
        "kind": "serenicity",
        "sensor_type_code": "detoxio",
        "collector_config_key": "serenicity-disabled",
        "name": "Detoxio Laboratoire",
        "is_active": False,
        "color": "#EA580C",
        "external_id": "920002",
        "latitude": 43.6047,
        "longitude": 1.4442,
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert source rows and their specialized records."""
    for source in SOURCES:
        source_id = _find_existing_specialized_source_id(connection, context, source)
        if source_id is None:
            source_id = _insert_source(connection, context, source)
        else:
            _update_source(connection, context, source_id, source)

        if source["kind"] == "ogo":
            _upsert_ogo_source(connection, context, source_id, source)
        else:
            _upsert_serenicity_source(connection, context, source_id, source)

        context.source_ids[str(source["key"])] = source_id

    return SeedResult("sources", len(SOURCES))


def _find_existing_specialized_source_id(
    connection: Connection,
    context: SeedContext,
    source: dict[str, Any],
) -> int | None:
    if source["kind"] == "ogo":
        ogo_sources = context.table("ogo_sources")
        row = connection.execute(
            select(ogo_sources.c.source_id).where(
                ogo_sources.c.domain_name == source["domain_name"]
            )
        ).first()
    else:
        serenicity_sources = context.table("serenicity_sources")
        row = connection.execute(
            select(serenicity_sources.c.source_id).where(
                serenicity_sources.c.external_id == source["external_id"]
            )
        ).first()

    if row is None:
        return None
    return int(row[0])


def _base_source_values(context: SeedContext, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "sensor_type_id": context.sensor_type_ids[str(source["sensor_type_code"])],
        "attacks_collector_config_id": context.collector_config_ids[
            str(source["collector_config_key"])
        ],
        "name": source["name"],
        "is_active": source["is_active"],
        "color": source["color"],
    }


def _insert_source(
    connection: Connection,
    context: SeedContext,
    source: dict[str, Any],
) -> int:
    sources = context.table("sources")
    row = connection.execute(
        insert(sources)
        .values(_base_source_values(context, source))
        .returning(sources.c.id)
    ).first()
    if row is None:
        raise RuntimeError(f"Unable to insert source {source['key']}")
    return int(row[0])


def _update_source(
    connection: Connection,
    context: SeedContext,
    source_id: int,
    source: dict[str, Any],
) -> None:
    sources = context.table("sources")
    connection.execute(
        update(sources)
        .where(sources.c.id == source_id)
        .values(_base_source_values(context, source) | {"updated_at": func.now()})
    )


def _upsert_ogo_source(
    connection: Connection,
    context: SeedContext,
    source_id: int,
    source: dict[str, Any],
) -> None:
    ogo_sources = context.table("ogo_sources")
    statement = pg_insert(ogo_sources).values(
        {
            "source_id": source_id,
            "domain_name": source["domain_name"],
            "organization_codes": source["organization_codes"],
        }
    )
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[ogo_sources.c.source_id],
            set_={
                "domain_name": statement.excluded.domain_name,
                "organization_codes": statement.excluded.organization_codes,
            },
        )
    )


def _upsert_serenicity_source(
    connection: Connection,
    context: SeedContext,
    source_id: int,
    source: dict[str, Any],
) -> None:
    serenicity_sources = context.table("serenicity_sources")
    statement = pg_insert(serenicity_sources).values(
        {
            "source_id": source_id,
            "external_id": source["external_id"],
            "latitude": source["latitude"],
            "longitude": source["longitude"],
        }
    )
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[serenicity_sources.c.source_id],
            set_={
                "external_id": statement.excluded.external_id,
                "latitude": statement.excluded.latitude,
                "longitude": statement.excluded.longitude,
            },
        )
    )


def assert_unique_specialized_identities() -> None:
    """Keep fixture identities safe before any database write."""
    ogo_domains = [
        source["domain_name"] for source in SOURCES if source["kind"] == "ogo"
    ]
    serenicity_ids = [
        source["external_id"] for source in SOURCES if source["kind"] == "serenicity"
    ]
    if len(ogo_domains) != len(set(ogo_domains)):
        raise RuntimeError("Duplicate OGO domain names in development seed data")
    if len(serenicity_ids) != len(set(serenicity_ids)):
        raise RuntimeError("Duplicate Serenicity external ids in development seed data")
