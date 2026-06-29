#!/usr/bin/env python3
"""Create a complete development dataset in PostgreSQL."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from datetime import UTC, datetime
import os
from pathlib import Path
import sys

from sqlalchemy import Connection, create_engine, inspect
from sqlalchemy.exc import SQLAlchemyError

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.db.dev_seed import (  # noqa: E402
    attacks,
    attacks_collector_config,
    common_ip_alert_sources,
    common_ip_alerts,
    cti_config,
    retention_policies,
    scheduler_state,
    sensor_types,
    smtp_config,
    sources,
)
from scripts.db.dev_seed.context import (  # noqa: E402
    REQUIRED_TABLES,
    SeedContext,
    SeedResult,
    load_schema_metadata,
    validate_metadata_tables,
)

SeedStep = Callable[[Connection, SeedContext], SeedResult]

SEED_STEPS: tuple[tuple[str, SeedStep], ...] = (
    ("sensor_types", sensor_types.seed),
    ("attacks_collector_config", attacks_collector_config.seed),
    ("sources", sources.seed),
    ("scheduler_state", scheduler_state.seed),
    ("attacks", attacks.seed),
    ("common_ip_alerts", common_ip_alerts.seed),
    ("common_ip_alert_sources", common_ip_alert_sources.seed),
    ("cti_config", cti_config.seed),
    ("smtp_config", smtp_config.seed),
    ("retention_policies", retention_policies.seed),
)


class SeedDevError(RuntimeError):
    """Raised when the development seed cannot run safely."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Insert or update a complete development dataset."
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL", ""),
        help="PostgreSQL SQLAlchemy URL. Defaults to DATABASE_URL.",
    )
    parser.add_argument(
        "--anchor-now",
        default=None,
        help=(
            "Reference datetime used for relative fixture timestamps. "
            "Defaults to the current UTC time."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run every statement in a transaction and roll it back.",
    )
    return parser.parse_args(argv)


def resolve_database_url(raw_database_url: str) -> str:
    """Return a non-empty database URL or fail with a clear message."""
    database_url = raw_database_url.strip()
    if not database_url:
        raise SeedDevError("DATABASE_URL or --database-url is required.")
    return database_url


def parse_anchor_now(raw_anchor_now: str | None) -> datetime:
    """Parse the optional anchor datetime used by generated seed rows."""
    if raw_anchor_now is None:
        return datetime.now(UTC).replace(microsecond=0)

    try:
        parsed = datetime.fromisoformat(raw_anchor_now)
    except ValueError as exc:
        raise SeedDevError(
            "--anchor-now must be an ISO 8601 datetime, for example "
            "2026-06-29T12:00:00+00:00."
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).replace(microsecond=0)


def validate_database_tables(connection: Connection) -> None:
    """Ensure the target database has the current migrated schema."""
    inspector = inspect(connection)
    public_tables = set(inspector.get_table_names(schema="public"))
    missing_tables = [
        table_name for table_name in REQUIRED_TABLES if table_name not in public_tables
    ]
    if missing_tables:
        missing = ", ".join(missing_tables)
        raise SeedDevError(
            "The target database is missing required tables. "
            f"Run scripts/db/migrate.py first. Missing: {missing}"
        )


def run_seed(
    *,
    connection: Connection,
    anchor_now: datetime,
) -> list[SeedResult]:
    """Run all seed steps in dependency order."""
    schema_metadata = load_schema_metadata()
    validate_metadata_tables(schema_metadata)
    sources.assert_unique_specialized_identities()

    context = SeedContext(metadata=schema_metadata, now=anchor_now)
    return [step(connection, context) for _step_name, step in SEED_STEPS]


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    args = parse_args(argv)

    try:
        database_url = resolve_database_url(args.database_url)
        anchor_now = parse_anchor_now(args.anchor_now)
        engine = create_engine(database_url)
    except (SeedDevError, SQLAlchemyError) as exc:
        print(f"Cannot prepare development seed: {exc}", file=sys.stderr)
        return 1

    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                validate_database_tables(connection)
                results = run_seed(connection=connection, anchor_now=anchor_now)
            except Exception:
                transaction.rollback()
                raise

            if args.dry_run:
                transaction.rollback()
            else:
                transaction.commit()
    except Exception as exc:
        print(f"Development seed failed: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()

    mode = "dry-run rolled back" if args.dry_run else "committed"
    print(f"Development seed {mode} with anchor {anchor_now.isoformat()}.")
    for result in results:
        print(f"- {result.name}: {result.row_count} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
