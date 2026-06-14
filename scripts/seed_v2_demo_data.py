#!/usr/bin/env python3
"""Seed a complete Cyber Dashboard V2 demo dataset.

The script targets the schema described by the Alembic V2 migration and the
shared SQLAlchemy models in packages/database/models. It does not create or
migrate the schema; run `alembic upgrade head` first.

Examples:
    python scripts/seed_v2_demo_data.py
    python scripts/seed_v2_demo_data.py --reset --days 60 --attacks-per-day 40
    DATABASE_URL=postgresql://user:pass@localhost:5432/cyber_dashboard \
        python scripts/seed_v2_demo_data.py
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import random
import sys
from typing import Iterable

from sqlalchemy import create_engine, delete, func, inspect, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from packages.database.models import (  # noqa: E402
    Attack,
    AttacksCollectorConfig,
    AttacksCollectorType,
    CommonIpAlert,
    CommonIpAlertSource,
    CorrelationStatus,
    CtiConfig,
    OgoSource,
    OgoSourceOrganization,
    RetentionPolicy,
    SchedulerState,
    SerenicitySource,
    SensorType,
    SmtpConfig,
    Source,
    SourceAttacksCollectorConfig,
)


DEMO_PREFIX = "demo-v2"


SENSOR_TYPE_SEEDS = (
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


CTI_CONFIG_SEEDS = (
    {
        "code": "abuseipdb",
        "label": "AbuseIPDB",
        "is_key_required": True,
        "is_active": True,
        "encrypted_api_key": "demo-encrypted-abuseipdb-key",
        "api_key_hint": "****demo",
        "last_validation_status": "success",
    },
    {
        "code": "ipdata",
        "label": "IPData",
        "is_key_required": True,
        "is_active": True,
        "encrypted_api_key": "demo-encrypted-ipdata-key",
        "api_key_hint": "****data",
        "last_validation_status": "success",
    },
    {
        "code": "greynoise",
        "label": "GreyNoise",
        "is_key_required": True,
        "is_active": False,
        "encrypted_api_key": None,
        "api_key_hint": None,
        "last_validation_status": "not_tested",
    },
    {
        "code": "virustotal",
        "label": "VirusTotal",
        "is_key_required": True,
        "is_active": True,
        "encrypted_api_key": "demo-encrypted-virustotal-key",
        "api_key_hint": "****vt",
        "last_validation_status": "success",
    },
    {
        "code": "shodan",
        "label": "Shodan",
        "is_key_required": True,
        "is_active": False,
        "encrypted_api_key": None,
        "api_key_hint": None,
        "last_validation_status": "not_tested",
    },
    {
        "code": "rdap",
        "label": "RDAP / WHOIS",
        "is_key_required": False,
        "is_active": True,
        "encrypted_api_key": None,
        "api_key_hint": None,
        "last_validation_status": "success",
    },
    {
        "code": "reverse_dns",
        "label": "Reverse DNS",
        "is_key_required": False,
        "is_active": True,
        "encrypted_api_key": None,
        "api_key_hint": None,
        "last_validation_status": "success",
    },
)


COLLECTOR_CONFIG_SEEDS = (
    {
        "name": "OGO Demo EU",
        "collector_type": AttacksCollectorType.OGO,
        "encrypted_email": "demo-encrypted-ogo@example.test",
        "email_hint": "o***@demo",
        "encrypted_api_key": "demo-encrypted-ogo-key",
        "api_key_hint": "****ogo",
        "is_active": True,
        "inventory_requested": False,
        "last_validation_status": "success",
    },
    {
        "name": "OGO Demo Partner",
        "collector_type": AttacksCollectorType.OGO,
        "encrypted_email": "demo-encrypted-partner@example.test",
        "email_hint": "p***@demo",
        "encrypted_api_key": "demo-encrypted-ogo-partner-key",
        "api_key_hint": "****part",
        "is_active": True,
        "inventory_requested": False,
        "last_validation_status": "success",
    },
    {
        "name": "Serenicity Demo",
        "collector_type": AttacksCollectorType.SERENICITY,
        "encrypted_email": None,
        "email_hint": None,
        "encrypted_api_key": "demo-encrypted-serenicity-key",
        "api_key_hint": "****sere",
        "is_active": True,
        "inventory_requested": False,
        "last_validation_status": "success",
    },
)


@dataclass(frozen=True)
class SourceSeed:
    key: str
    sensor_type_code: str
    name: str
    color: str
    is_active: bool
    collector_names: tuple[str, ...]
    domain_name: str | None = None
    organizations_by_config: dict[str, tuple[str, ...]] | None = None
    external_id: str | None = None
    latitude: float | None = None
    longitude: float | None = None


SOURCE_SEEDS = (
    SourceSeed(
        key="ogo_portal",
        sensor_type_code="waf",
        name="Portail client",
        color="#D8C4A5",
        is_active=True,
        collector_names=("OGO Demo EU",),
        domain_name="portal.demo-v2.test",
        organizations_by_config={"OGO Demo EU": ("VAUCLAIRE", "PORTAL")},
    ),
    SourceSeed(
        key="ogo_extranet",
        sensor_type_code="waf",
        name="Extranet RH",
        color="#C9B79A",
        is_active=True,
        collector_names=("OGO Demo EU",),
        domain_name="rh.demo-v2.test",
        organizations_by_config={"OGO Demo EU": ("VAUCLAIRE", "HR")},
    ),
    SourceSeed(
        key="ogo_api",
        sensor_type_code="waf",
        name="API paiement",
        color="#BFAE91",
        is_active=True,
        collector_names=("OGO Demo EU", "OGO Demo Partner"),
        domain_name="api-pay.demo-v2.test",
        organizations_by_config={
            "OGO Demo EU": ("VAUCLAIRE", "PAYMENT"),
            "OGO Demo Partner": ("PARTNER",),
        },
    ),
    SourceSeed(
        key="ogo_shop",
        sensor_type_code="waf",
        name="Boutique publique",
        color="#E7D8C0",
        is_active=False,
        collector_names=("OGO Demo Partner",),
        domain_name="shop.demo-v2.test",
        organizations_by_config={"OGO Demo Partner": ("PARTNER", "SHOP")},
    ),
    SourceSeed(
        key="detoxio_paris",
        sensor_type_code="detoxio",
        name="Detoxio Paris",
        color="#9BB7B5",
        is_active=True,
        collector_names=("Serenicity Demo",),
        external_id="200001",
        latitude=48.8566,
        longitude=2.3522,
    ),
    SourceSeed(
        key="detoxio_lyon",
        sensor_type_code="detoxio",
        name="Detoxio Lyon",
        color="#8AAEAA",
        is_active=True,
        collector_names=("Serenicity Demo",),
        external_id="200002",
        latitude=45.7640,
        longitude=4.8357,
    ),
    SourceSeed(
        key="detoxio_lille",
        sensor_type_code="detoxio",
        name="Detoxio Lille",
        color="#B7CFCD",
        is_active=False,
        collector_names=("Serenicity Demo",),
        external_id="200003",
        latitude=50.6292,
        longitude=3.0573,
    ),
    SourceSeed(
        key="lurio_marseille",
        sensor_type_code="lurio",
        name="Lurio Marseille",
        color="#526957",
        is_active=True,
        collector_names=("Serenicity Demo",),
        external_id="300001",
        latitude=43.2965,
        longitude=5.3698,
    ),
    SourceSeed(
        key="lurio_nantes",
        sensor_type_code="lurio",
        name="Lurio Nantes",
        color="#617764",
        is_active=True,
        collector_names=("Serenicity Demo",),
        external_id="300002",
        latitude=47.2184,
        longitude=-1.5536,
    ),
    SourceSeed(
        key="lurio_toulouse",
        sensor_type_code="lurio",
        name="Lurio Toulouse",
        color="#78907A",
        is_active=True,
        collector_names=("Serenicity Demo",),
        external_id="300003",
        latitude=43.6047,
        longitude=1.4442,
    ),
)


COMMON_ATTACK_PATTERNS = {
    "198.51.100.23": ("ogo_portal", "detoxio_paris", "lurio_marseille"),
    "198.51.100.77": ("ogo_api", "detoxio_lyon", "lurio_nantes"),
    "203.0.113.41": ("ogo_extranet", "detoxio_paris", "lurio_toulouse"),
    "203.0.113.99": ("ogo_portal", "ogo_api", "lurio_marseille"),
    "192.0.2.150": ("detoxio_lyon", "lurio_nantes", "lurio_toulouse"),
}


ATTACK_TYPES = (
    "sql_injection",
    "xss",
    "path_traversal",
    "brute_force",
    "command_injection",
    "rce",
    "bot",
    "vulnerability_scan",
    "credential_stuffing",
    "malicious_probe",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a complete deterministic V2 demo dataset."
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL"),
        help="SQLAlchemy/PostgreSQL URL. Defaults to DATABASE_URL or DB_* env vars.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete rows generated by this script before reseeding.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=45,
        help="Number of days of attack history to generate.",
    )
    parser.add_argument(
        "--attacks-per-day",
        type=int,
        default=30,
        help="Approximate number of attacks generated per day.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260612,
        help="Random seed used for deterministic attack generation.",
    )
    return parser.parse_args()


def build_database_url(raw_url: str | None) -> str:
    if raw_url:
        return normalize_driver(raw_url)

    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5433")
    name = os.getenv("DB_NAME") or os.getenv("POSTGRES_DB", "postgres")
    user = os.getenv("DB_USER") or os.getenv("POSTGRES_USER", "postgres")
    password = os.getenv("DB_PASSWORD") or os.getenv("POSTGRES_PASSWORD", "postgres")
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}"


def normalize_driver(url: str) -> str:
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return url


def ensure_schema(engine) -> None:
    table_names = set(inspect(engine).get_table_names())
    required_tables = {
        Attack.__tablename__,
        AttacksCollectorConfig.__tablename__,
        CommonIpAlert.__tablename__,
        CommonIpAlertSource.__tablename__,
        CtiConfig.__tablename__,
        OgoSource.__tablename__,
        OgoSourceOrganization.__tablename__,
        RetentionPolicy.__tablename__,
        SchedulerState.__tablename__,
        SerenicitySource.__tablename__,
        SensorType.__tablename__,
        SmtpConfig.__tablename__,
        Source.__tablename__,
        SourceAttacksCollectorConfig.__tablename__,
    }
    missing_tables = sorted(required_tables - table_names)
    if missing_tables:
        joined = ", ".join(missing_tables)
        raise RuntimeError(
            "Missing V2 tables: "
            f"{joined}. Run the Alembic migrations before seeding."
        )


def upsert_one(session: Session, model, filters: dict, values: dict):
    row = session.execute(select(model).filter_by(**filters)).scalars().first()
    now = datetime.now(UTC).replace(microsecond=0)

    if row is None:
        row = model(**filters, **values)
        if hasattr(row, "created_at") and getattr(row, "created_at", None) is None:
            row.created_at = now
        if hasattr(row, "updated_at") and getattr(row, "updated_at", None) is None:
            row.updated_at = now
        session.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
        if hasattr(row, "updated_at"):
            row.updated_at = now

    return row


def seed_reference_data(session: Session) -> dict[str, SensorType]:
    now = datetime.now(UTC).replace(microsecond=0)

    sensor_types: dict[str, SensorType] = {}
    for seed in SENSOR_TYPE_SEEDS:
        sensor_type = upsert_one(
            session,
            SensorType,
            {"code": seed["code"]},
            {
                "label": seed["label"],
                "category": seed["category"],
                "color": seed["color"],
            },
        )
        sensor_types[sensor_type.code] = sensor_type

    for seed in CTI_CONFIG_SEEDS:
        upsert_one(
            session,
            CtiConfig,
            {"code": seed["code"]},
            {
                "label": seed["label"],
                "is_key_required": seed["is_key_required"],
                "is_active": seed["is_active"],
                "encrypted_api_key": seed["encrypted_api_key"],
                "api_key_hint": seed["api_key_hint"],
                "last_validation_status": seed["last_validation_status"],
                "last_validation_at": now
                if seed["last_validation_status"] == "success"
                else None,
                "last_validation_error": None,
            },
        )

    upsert_one(
        session,
        SmtpConfig,
        {"id": 1},
        {
            "smtp_host": "smtp.demo-v2.test",
            "smtp_port": 587,
            "smtp_user": "alerts@demo-v2.test",
            "encrypted_smtp_password": "demo-encrypted-smtp-password",
            "smtp_password_hint": "****smtp",
            "smtp_from": "alerts@demo-v2.test",
            "smtp_from_name": "Cyber Dashboard Demo",
            "is_active": True,
            "last_validation_status": "success",
            "last_validation_at": now,
            "last_validation_error": None,
        },
    )

    for target_table, retention_days in (
        ("attacks", 365),
        ("common_ip_alerts", 180),
    ):
        upsert_one(
            session,
            RetentionPolicy,
            {"target_table": target_table},
            {
                "retention_days": retention_days,
                "is_active": True,
                "last_run_at": now - timedelta(days=1),
                "last_deleted_count": 0,
                "last_error": None,
            },
        )

    session.flush()
    return sensor_types


def seed_collector_configs(session: Session) -> dict[str, AttacksCollectorConfig]:
    now = datetime.now(UTC).replace(microsecond=0)
    configs: dict[str, AttacksCollectorConfig] = {}

    for seed in COLLECTOR_CONFIG_SEEDS:
        config = upsert_one(
            session,
            AttacksCollectorConfig,
            {
                "collector_type": seed["collector_type"],
                "name": seed["name"],
            },
            {
                "encrypted_email": seed["encrypted_email"],
                "email_hint": seed["email_hint"],
                "encrypted_api_key": seed["encrypted_api_key"],
                "api_key_hint": seed["api_key_hint"],
                "is_active": seed["is_active"],
                "inventory_requested": seed["inventory_requested"],
                "last_validation_status": seed["last_validation_status"],
                "last_validation_at": now,
                "last_validation_error": None,
            },
        )
        configs[config.name] = config

    session.flush()
    return configs


def find_existing_source(session: Session, seed: SourceSeed, sensor_type_id: int):
    if seed.domain_name:
        ogo_source = session.execute(
            select(OgoSource).where(OgoSource.domain_name == seed.domain_name)
        ).scalars().first()
        if ogo_source is not None:
            return ogo_source.source

    if seed.external_id:
        serenicity_source = session.execute(
            select(SerenicitySource).where(
                SerenicitySource.external_id == seed.external_id
            )
        ).scalars().first()
        if serenicity_source is not None:
            return serenicity_source.source

    return session.execute(
        select(Source).where(
            Source.name == seed.name,
            Source.sensor_type_id == sensor_type_id,
        )
    ).scalars().first()


def seed_sources(
    session: Session,
    sensor_types: dict[str, SensorType],
    configs: dict[str, AttacksCollectorConfig],
) -> dict[str, Source]:
    now = datetime.now(UTC).replace(microsecond=0)
    sources: dict[str, Source] = {}

    for seed in SOURCE_SEEDS:
        sensor_type = sensor_types[seed.sensor_type_code]
        source = find_existing_source(session, seed, sensor_type.id)

        if source is None:
            source = Source(
                sensor_type_id=sensor_type.id,
                name=seed.name,
                is_active=seed.is_active,
                color=seed.color,
                created_at=now - timedelta(days=60),
                updated_at=now,
            )
            session.add(source)
        else:
            source.sensor_type_id = sensor_type.id
            source.name = seed.name
            source.is_active = seed.is_active
            source.color = seed.color
            source.updated_at = now

        session.flush()

        if seed.domain_name:
            ogo_source = session.get(OgoSource, source.id)
            if ogo_source is None:
                ogo_source = OgoSource(source_id=source.id)
                session.add(ogo_source)
            ogo_source.domain_name = seed.domain_name

        if seed.external_id:
            serenicity_source = session.get(SerenicitySource, source.id)
            if serenicity_source is None:
                serenicity_source = SerenicitySource(source_id=source.id)
                session.add(serenicity_source)
            serenicity_source.external_id = seed.external_id
            serenicity_source.latitude = seed.latitude
            serenicity_source.longitude = seed.longitude

        for config_name in seed.collector_names:
            config = configs[config_name]
            link = session.get(
                SourceAttacksCollectorConfig,
                {
                    "source_id": source.id,
                    "attacks_collector_config_id": config.id,
                },
            )
            if link is None:
                session.add(
                    SourceAttacksCollectorConfig(
                        source_id=source.id,
                        attacks_collector_config_id=config.id,
                    )
                )

            for organization_code in (
                seed.organizations_by_config or {}
            ).get(config_name, ()):
                organization = session.get(
                    OgoSourceOrganization,
                    {
                        "source_id": source.id,
                        "attacks_collector_config_id": config.id,
                        "organization_code": organization_code,
                    },
                )
                if organization is None:
                    session.add(
                        OgoSourceOrganization(
                            source_id=source.id,
                            attacks_collector_config_id=config.id,
                            organization_code=organization_code,
                        )
                    )

        sources[seed.key] = source

    session.flush()
    return sources


def build_attack_rows(
    *,
    sources_by_key: dict[str, Source],
    days: int,
    attacks_per_day: int,
    seed_value: int,
) -> list[dict]:
    rng = random.Random(seed_value)
    now = datetime.now(UTC).replace(microsecond=0)
    days = max(days, 1)
    attacks_per_day = max(attacks_per_day, 1)

    active_source_keys = [
        seed.key for seed in SOURCE_SEEDS if sources_by_key[seed.key].is_active
    ]
    all_source_keys = [seed.key for seed in SOURCE_SEEDS]

    rows: list[dict] = []
    event_index = 0

    def add_row(
        *,
        source_key: str,
        attacker_ip: str,
        occurred_at: datetime,
        attack_type: str,
        is_common: bool,
    ) -> None:
        nonlocal event_index
        source = sources_by_key[source_key]
        collected_at = occurred_at + timedelta(minutes=rng.randint(1, 20))
        status = (
            CorrelationStatus.COMPLETED.value
            if is_common
            else rng.choice(
                (
                    CorrelationStatus.PENDING.value,
                    CorrelationStatus.PROCESSING.value,
                    CorrelationStatus.COMPLETED.value,
                )
            )
        )
        rows.append(
            {
                "deduplication_id": (
                    f"{DEMO_PREFIX}:{source_key}:{event_index}:"
                    f"{attacker_ip}:{occurred_at.isoformat()}"
                ),
                "source_id": source.id,
                "source_event_id": f"{DEMO_PREFIX}-{event_index:06d}",
                "attacker_ip": attacker_ip,
                "occurred_at": occurred_at,
                "collected_at": collected_at,
                "attack_type": attack_type,
                "raw_payload": {
                    "dataset": DEMO_PREFIX,
                    "source_key": source_key,
                    "severity": rng.choice(("low", "medium", "high", "critical")),
                    "country": rng.choice(("FR", "US", "NL", "DE", "SG", "BR")),
                    "confidence": rng.randint(55, 99),
                    "rule": f"demo-rule-{rng.randint(1, 12)}",
                },
                "correlation_status": status,
            }
        )
        event_index += 1

    for day_offset in range(days):
        day_start = now - timedelta(days=day_offset)

        if day_offset % 2 == 0:
            for common_ip, source_keys in COMMON_ATTACK_PATTERNS.items():
                for pattern_index, source_key in enumerate(source_keys):
                    occurred_at = day_start.replace(
                        hour=(2 + pattern_index * 3 + day_offset) % 24,
                        minute=(day_offset * 7 + pattern_index * 11) % 60,
                        second=0,
                    )
                    add_row(
                        source_key=source_key,
                        attacker_ip=common_ip,
                        occurred_at=occurred_at,
                        attack_type=ATTACK_TYPES[
                            (day_offset + pattern_index) % len(ATTACK_TYPES)
                        ],
                        is_common=True,
                    )

        for slot in range(attacks_per_day):
            source_key = rng.choice(active_source_keys)
            if slot % 11 == 0:
                source_key = rng.choice(all_source_keys)
            host = 10 + ((day_offset * attacks_per_day + slot) % 230)
            subnet = rng.choice(("192.0.2", "198.51.100", "203.0.113"))
            attacker_ip = f"{subnet}.{host}"
            if attacker_ip in COMMON_ATTACK_PATTERNS:
                attacker_ip = f"{subnet}.{host + 1}"
            occurred_at = day_start.replace(
                hour=slot % 24,
                minute=(slot * 13 + day_offset) % 60,
                second=rng.randint(0, 59),
            )
            add_row(
                source_key=source_key,
                attacker_ip=attacker_ip,
                occurred_at=occurred_at,
                attack_type=rng.choice(ATTACK_TYPES),
                is_common=False,
            )

    return rows


def seed_attacks(
    session: Session,
    sources_by_key: dict[str, Source],
    *,
    days: int,
    attacks_per_day: int,
    seed_value: int,
) -> int:
    rows = build_attack_rows(
        sources_by_key=sources_by_key,
        days=days,
        attacks_per_day=attacks_per_day,
        seed_value=seed_value,
    )
    if not rows:
        return 0

    statement = pg_insert(Attack).values(rows)
    statement = statement.on_conflict_do_nothing(
        index_elements=[Attack.deduplication_id]
    )
    result = session.execute(statement)
    session.flush()
    return int(result.rowcount or 0)


def seed_alerts_from_demo_attacks(session: Session) -> int:
    grouped_rows = session.execute(
        select(
            Attack.attacker_ip,
            Attack.source_id,
            func.min(Attack.occurred_at),
            func.max(Attack.occurred_at),
            func.count(Attack.id),
        )
        .where(Attack.deduplication_id.like(f"{DEMO_PREFIX}:%"))
        .group_by(Attack.attacker_ip, Attack.source_id)
    ).all()

    rows_by_ip: dict[str, list] = defaultdict(list)
    for attacker_ip, source_id, first_seen_at, last_seen_at, hit_count in grouped_rows:
        rows_by_ip[str(attacker_ip)].append(
            {
                "source_id": int(source_id),
                "first_seen_at": first_seen_at,
                "last_seen_at": last_seen_at,
                "hit_count": int(hit_count),
            }
        )

    alert_count = 0
    now = datetime.now(UTC).replace(microsecond=0)
    for attacker_ip, source_rows in rows_by_ip.items():
        if len(source_rows) < 2:
            continue

        first_seen_at = min(row["first_seen_at"] for row in source_rows)
        last_seen_at = max(row["last_seen_at"] for row in source_rows)
        status = "open" if last_seen_at >= now - timedelta(days=14) else "acknowledged"

        alert = upsert_one(
            session,
            CommonIpAlert,
            {"attacker_ip": attacker_ip},
            {
                "first_seen_at": first_seen_at,
                "last_seen_at": last_seen_at,
                "distinct_source_count": len(source_rows),
                "status": status,
            },
        )
        session.flush()

        for source_row in source_rows:
            alert_source = session.get(
                CommonIpAlertSource,
                {
                    "alert_id": alert.id,
                    "source_id": source_row["source_id"],
                },
            )
            if alert_source is None:
                alert_source = CommonIpAlertSource(
                    alert_id=alert.id,
                    source_id=source_row["source_id"],
                )
                session.add(alert_source)

            alert_source.first_seen_at = source_row["first_seen_at"]
            alert_source.last_seen_at = source_row["last_seen_at"]
            alert_source.hit_count = source_row["hit_count"]

        alert_count += 1

    session.flush()
    return alert_count


def seed_scheduler_state(
    session: Session,
    sources_by_key: dict[str, Source],
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    for index, source_seed in enumerate(SOURCE_SEEDS):
        source = sources_by_key[source_seed.key]
        state = session.get(SchedulerState, source.id)
        if state is None:
            state = SchedulerState(source_id=source.id)
            session.add(state)

        inventory_at = now - timedelta(hours=2, minutes=index * 3)
        poll_at = now - timedelta(minutes=15 + index * 2)
        state.last_inventory_at = inventory_at
        state.last_inventory_status = "success"
        state.last_inventory_success_at = inventory_at
        state.last_inventory_error_at = None
        state.last_inventory_error_message = None

        state.last_poll_at = poll_at
        if source.is_active:
            state.last_collection_status = "success"
            state.last_collection_success_at = poll_at
            state.last_collection_error_at = None
            state.last_collection_error_message = None
        else:
            state.last_collection_status = "failed"
            state.last_collection_success_at = None
            state.last_collection_error_at = poll_at
            state.last_collection_error_message = (
                "Demo source inactive during last collection"
            )

    session.flush()


def delete_if_any(session: Session, model, column, values: Iterable) -> None:
    values = list(values)
    if not values:
        return
    session.execute(
        delete(model).where(column.in_(values)).execution_options(
            synchronize_session=False
        )
    )


def reset_demo_data(session: Session) -> None:
    source_names = [seed.name for seed in SOURCE_SEEDS]
    domain_names = [seed.domain_name for seed in SOURCE_SEEDS if seed.domain_name]
    external_ids = [seed.external_id for seed in SOURCE_SEEDS if seed.external_id]
    config_names = [seed["name"] for seed in COLLECTOR_CONFIG_SEEDS]
    common_ips = list(COMMON_ATTACK_PATTERNS)

    source_ids = set(
        session.scalars(select(Source.id).where(Source.name.in_(source_names))).all()
    )
    source_ids.update(
        session.scalars(
            select(OgoSource.source_id).where(OgoSource.domain_name.in_(domain_names))
        ).all()
    )
    source_ids.update(
        session.scalars(
            select(SerenicitySource.source_id).where(
                SerenicitySource.external_id.in_(external_ids)
            )
        ).all()
    )

    config_ids = set(
        session.scalars(
            select(AttacksCollectorConfig.id).where(
                AttacksCollectorConfig.name.in_(config_names)
            )
        ).all()
    )

    alert_ids = set(
        session.scalars(
            select(CommonIpAlert.id).where(CommonIpAlert.attacker_ip.in_(common_ips))
        ).all()
    )
    if source_ids:
        alert_ids.update(
            session.scalars(
                select(CommonIpAlertSource.alert_id).where(
                    CommonIpAlertSource.source_id.in_(source_ids)
                )
            ).all()
        )

    delete_if_any(session, CommonIpAlertSource, CommonIpAlertSource.alert_id, alert_ids)
    delete_if_any(session, CommonIpAlertSource, CommonIpAlertSource.source_id, source_ids)
    delete_if_any(session, CommonIpAlert, CommonIpAlert.id, alert_ids)

    session.execute(
        delete(Attack)
        .where(Attack.deduplication_id.like(f"{DEMO_PREFIX}:%"))
        .execution_options(synchronize_session=False)
    )

    delete_if_any(session, SchedulerState, SchedulerState.source_id, source_ids)
    delete_if_any(
        session,
        OgoSourceOrganization,
        OgoSourceOrganization.attacks_collector_config_id,
        config_ids,
    )
    delete_if_any(session, OgoSourceOrganization, OgoSourceOrganization.source_id, source_ids)
    delete_if_any(
        session,
        SourceAttacksCollectorConfig,
        SourceAttacksCollectorConfig.attacks_collector_config_id,
        config_ids,
    )
    delete_if_any(
        session,
        SourceAttacksCollectorConfig,
        SourceAttacksCollectorConfig.source_id,
        source_ids,
    )
    delete_if_any(session, OgoSource, OgoSource.source_id, source_ids)
    delete_if_any(session, SerenicitySource, SerenicitySource.source_id, source_ids)
    delete_if_any(session, Source, Source.id, source_ids)
    delete_if_any(session, AttacksCollectorConfig, AttacksCollectorConfig.id, config_ids)
    session.flush()


def count_demo_attacks(session: Session) -> int:
    return int(
        session.scalar(
            select(func.count(Attack.id)).where(
                Attack.deduplication_id.like(f"{DEMO_PREFIX}:%")
            )
        )
        or 0
    )


def main() -> None:
    args = parse_args()
    database_url = build_database_url(args.database_url)
    engine = create_engine(database_url, future=True)
    ensure_schema(engine)

    with Session(engine) as session:
        if args.reset:
            reset_demo_data(session)

        sensor_types = seed_reference_data(session)
        configs = seed_collector_configs(session)
        sources = seed_sources(session, sensor_types, configs)
        inserted_attacks = seed_attacks(
            session,
            sources,
            days=args.days,
            attacks_per_day=args.attacks_per_day,
            seed_value=args.seed,
        )
        alert_count = seed_alerts_from_demo_attacks(session)
        seed_scheduler_state(session, sources)
        total_demo_attacks = count_demo_attacks(session)
        session.commit()

    print("Cyber Dashboard V2 demo dataset ready")
    print(f"- sources: {len(SOURCE_SEEDS)}")
    print(f"- collector configs: {len(COLLECTOR_CONFIG_SEEDS)}")
    print(f"- attacks inserted this run: {inserted_attacks}")
    print(f"- demo attacks total: {total_demo_attacks}")
    print(f"- common IP alerts: {alert_count}")


if __name__ == "__main__":
    main()
