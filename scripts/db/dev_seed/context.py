"""Shared helpers for the development seed."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import MetaData, Table

from cyber_dashboard_database.models import load_all_models, metadata

REQUIRED_TABLES = (
    "sensor_types",
    "attacks_collector_config",
    "sources",
    "ogo_sources",
    "serenicity_sources",
    "scheduler_state",
    "attacks",
    "common_ip_alerts",
    "common_ip_alert_sources",
    "cti_config",
    "smtp_config",
    "retention_policies",
)


@dataclass(frozen=True, slots=True)
class SeedResult:
    """Summary returned by a seed step."""

    name: str
    row_count: int


@dataclass(slots=True)
class SeedContext:
    """Mutable identifiers shared between seed steps."""

    metadata: MetaData
    now: datetime
    sensor_type_ids: dict[str, int] = field(default_factory=dict)
    collector_config_ids: dict[str, int] = field(default_factory=dict)
    source_ids: dict[str, int] = field(default_factory=dict)
    alert_ids: dict[str, int] = field(default_factory=dict)

    def table(self, table_name: str) -> Table:
        return self.metadata.tables[table_name]


def load_schema_metadata() -> MetaData:
    """Load the shared SQLAlchemy metadata with every model table registered."""
    load_all_models()
    return metadata


def validate_metadata_tables(schema_metadata: MetaData) -> None:
    """Fail early when a model table is missing from SQLAlchemy metadata."""
    missing_tables = [
        table_name
        for table_name in REQUIRED_TABLES
        if table_name not in schema_metadata.tables
    ]
    if missing_tables:
        missing = ", ".join(missing_tables)
        raise RuntimeError(f"Missing tables from SQLAlchemy metadata: {missing}")
