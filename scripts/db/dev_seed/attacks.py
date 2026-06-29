"""Seed data for attacks."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import Connection
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .context import SeedContext, SeedResult

ATTACK_PATTERNS = (
    {
        "source_key": "ogo-portal",
        "attacker_ip": "203.0.113.10",
        "attack_type": "sql_injection",
        "count": 8,
        "first_hours_ago": 4,
        "spacing_hours": 18,
        "correlation_status": "completed",
    },
    {
        "source_key": "ogo-extranet",
        "attacker_ip": "203.0.113.10",
        "attack_type": "credential_stuffing",
        "count": 6,
        "first_hours_ago": 2,
        "spacing_hours": 22,
        "correlation_status": "completed",
    },
    {
        "source_key": "lurio-main",
        "attacker_ip": "203.0.113.10",
        "attack_type": "honeypot_probe",
        "count": 7,
        "first_hours_ago": 1,
        "spacing_hours": 16,
        "correlation_status": "completed",
    },
    {
        "source_key": "detoxio-main",
        "attacker_ip": "203.0.113.10",
        "attack_type": "port_scan",
        "count": 5,
        "first_hours_ago": 6,
        "spacing_hours": 20,
        "correlation_status": "completed",
    },
    {
        "source_key": "ogo-portal",
        "attacker_ip": "198.51.100.23",
        "attack_type": "xss",
        "count": 5,
        "first_hours_ago": 8,
        "spacing_hours": 24,
        "correlation_status": "completed",
    },
    {
        "source_key": "detoxio-main",
        "attacker_ip": "198.51.100.23",
        "attack_type": "port_scan",
        "count": 4,
        "first_hours_ago": 12,
        "spacing_hours": 27,
        "correlation_status": "completed",
    },
    {
        "source_key": "lurio-backup",
        "attacker_ip": "192.0.2.77",
        "attack_type": "honeypot_probe",
        "count": 4,
        "first_hours_ago": 16,
        "spacing_hours": 36,
        "correlation_status": "failed",
    },
    {
        "source_key": "ogo-extranet",
        "attacker_ip": "192.0.2.140",
        "attack_type": "path_traversal",
        "count": 6,
        "first_hours_ago": 3,
        "spacing_hours": 14,
        "correlation_status": "pending",
    },
    {
        "source_key": "detoxio-lab",
        "attacker_ip": "198.51.100.88",
        "attack_type": None,
        "count": 3,
        "first_hours_ago": 40,
        "spacing_hours": 48,
        "correlation_status": "pending",
    },
)


def seed(connection: Connection, context: SeedContext) -> SeedResult:
    """Upsert deterministic attack rows relative to the seed anchor time."""
    table = context.table("attacks")
    values = _build_rows(context)
    statement = pg_insert(table).values(values)
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c.deduplication_id],
            set_={
                "source_id": statement.excluded.source_id,
                "source_event_id": statement.excluded.source_event_id,
                "attacker_ip": statement.excluded.attacker_ip,
                "occurred_at": statement.excluded.occurred_at,
                "collected_at": statement.excluded.collected_at,
                "attack_type": statement.excluded.attack_type,
                "raw_payload": statement.excluded.raw_payload,
                "correlation_status": statement.excluded.correlation_status,
            },
        )
    )
    return SeedResult("attacks", len(values))


def _build_rows(context: SeedContext) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for pattern_index, pattern in enumerate(ATTACK_PATTERNS, start=1):
        source_key = str(pattern["source_key"])
        source_id = context.source_ids[source_key]
        count = int(pattern["count"])
        first_hours_ago = int(pattern["first_hours_ago"])
        spacing_hours = int(pattern["spacing_hours"])

        for event_index in range(count):
            occurred_at = context.now - timedelta(
                hours=first_hours_ago + event_index * spacing_hours
            )
            source_event_id = f"dev-{source_key}-{pattern_index}-{event_index + 1}"
            rows.append(
                {
                    "deduplication_id": f"dev-seed-v1:{source_key}:{pattern_index}:{event_index + 1}",
                    "source_id": source_id,
                    "source_event_id": source_event_id,
                    "attacker_ip": pattern["attacker_ip"],
                    "occurred_at": occurred_at,
                    "collected_at": occurred_at + timedelta(minutes=5),
                    "attack_type": pattern["attack_type"],
                    "raw_payload": {
                        "fixture": "dev-seed-v1",
                        "source_key": source_key,
                        "source_event_id": source_event_id,
                        "pattern_index": pattern_index,
                    },
                    "correlation_status": pattern["correlation_status"],
                }
            )
    return rows
