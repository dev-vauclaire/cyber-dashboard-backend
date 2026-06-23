#!/usr/bin/env python3
"""Bootstrap Alembic migrations depending on the current database state."""

from __future__ import annotations

from configparser import ConfigParser
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import time
import subprocess
import tempfile
from typing import Any, Iterable, Literal

V1_BASELINE_REVISION = "6d98af97a0e5"
PUBLIC_SCHEMA = "public"
ALEMBIC_VERSION_TABLE = "alembic_version"
DATABASE_WAIT_TIMEOUT_SECONDS = 60
DATABASE_WAIT_POLL_SECONDS = 2

LEGACY_V1_REQUIRED_TABLES = {
    "sensor_types",
    "sources",
    "attacks",
    "common_ip_alerts",
    "common_ip_alert_sources",
    "scheduler_state",
}

LEGACY_V1_REQUIRED_COLUMNS = {
    "sources": {
        "id",
        "sensor_type_id",
        "external_id",
        "name",
        "latitude",
        "longitude",
        "is_active",
        "created_at",
        "color",
    },
    "attacks": {
        "id",
        "deduplication_id",
        "source_id",
        "attacker_ip",
        "occurred_at",
        "collected_at",
        "attack_type",
        "raw_payload",
        "correlation_status",
    },
}

DetectedState = Literal["alembic_versioned", "empty", "legacy_v1", "unknown"]
MigrationPlan = Literal[
    "upgrade_head",
    "stamp_baseline_then_upgrade",
    "abort_unknown_database",
]


class MigrationBootstrapError(RuntimeError):
    """Raised when the migration bootstrap cannot continue safely."""


@dataclass(frozen=True, slots=True)
class DatabaseInspectionResult:
    """Inspection summary used to choose the Alembic bootstrap flow."""

    detected_state: DetectedState
    has_alembic_version_table: bool
    current_revision: str | None
    business_tables: tuple[str, ...]
    is_empty: bool
    matches_legacy_v1: bool


def _get_positive_int_env(name: str, default: int) -> int:
    """Read an optional positive integer environment variable."""
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    try:
        value = int(raw_value.strip())
    except ValueError as exc:
        raise MigrationBootstrapError(
            f"{name} must be a positive integer when provided."
        ) from exc

    if value <= 0:
        raise MigrationBootstrapError(
            f"{name} must be a positive integer when provided."
        )

    return value


def require_database_url() -> str:
    """Read the database URL from the environment."""
    database_url = os.getenv("DATABASE_URL")
    if database_url is None or not database_url.strip():
        raise MigrationBootstrapError(
            "DATABASE_URL is required to run the migration bootstrap script."
        )
    return database_url.strip()


def resolve_baseline_revision() -> str:
    """Return the configured baseline revision for legacy V1 databases."""
    revision = os.getenv("V1_BASELINE_REVISION", V1_BASELINE_REVISION).strip()
    if not revision:
        raise MigrationBootstrapError(
            "V1_BASELINE_REVISION is required when a legacy V1 database needs stamping."
        )
    return revision


def _probe_database_connection(database_url: str) -> None:
    """Attempt a single SQLAlchemy connection against the target database."""
    try:
        from sqlalchemy import create_engine, text
        from sqlalchemy.exc import SQLAlchemyError
    except ModuleNotFoundError as exc:
        raise MigrationBootstrapError(
            "SQLAlchemy is required to wait for the database. "
            "Install the backend dependencies before running this script."
        ) from exc

    try:
        engine = create_engine(database_url)
    except SQLAlchemyError as exc:
        raise MigrationBootstrapError(
            f"Unable to create SQLAlchemy engine from DATABASE_URL: {exc}"
        ) from exc

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise MigrationBootstrapError(str(exc)) from exc
    finally:
        engine.dispose()


def wait_for_database(database_url: str) -> None:
    """Wait until the target PostgreSQL database accepts SQLAlchemy connections."""
    timeout_seconds = _get_positive_int_env(
        "DATABASE_WAIT_TIMEOUT_SECONDS",
        DATABASE_WAIT_TIMEOUT_SECONDS,
    )
    poll_seconds = _get_positive_int_env(
        "DATABASE_WAIT_POLL_SECONDS",
        DATABASE_WAIT_POLL_SECONDS,
    )
    deadline = time.monotonic() + timeout_seconds
    last_error: str | None = None

    while True:
        try:
            _probe_database_connection(database_url)
            return
        except MigrationBootstrapError as exc:
            last_error = str(exc)
            if time.monotonic() >= deadline:
                break

            print(
                "Database is not reachable yet; retrying in "
                f"{poll_seconds}s. Last error: {last_error}"
            )
            time.sleep(poll_seconds)

    raise MigrationBootstrapError(
        "Database did not become reachable before timeout. " f"Last error: {last_error}"
    )


def has_alembic_version_table(public_tables: Iterable[str]) -> bool:
    """Tell whether the public schema already contains Alembic metadata."""
    return ALEMBIC_VERSION_TABLE in set(public_tables)


def is_empty_database(public_tables: Iterable[str]) -> bool:
    """Tell whether the database has no business table yet."""
    business_tables = {
        table_name
        for table_name in public_tables
        if table_name != ALEMBIC_VERSION_TABLE
    }
    return len(business_tables) == 0


def matches_legacy_v1_schema(
    *,
    public_tables: Iterable[str],
    columns_by_table: dict[str, set[str]],
) -> bool:
    """Validate that the discovered schema matches the historical V1 layout."""
    table_names = set(public_tables)
    if not LEGACY_V1_REQUIRED_TABLES.issubset(table_names):
        return False

    for table_name, required_columns in LEGACY_V1_REQUIRED_COLUMNS.items():
        existing_columns = columns_by_table.get(table_name, set())
        if not required_columns.issubset(existing_columns):
            return False

    return True


def resolve_migration_plan(inspection: DatabaseInspectionResult) -> MigrationPlan:
    """Choose the safe bootstrap plan from the inspected database state."""
    if inspection.detected_state == "alembic_versioned":
        return "upgrade_head"
    if inspection.detected_state == "empty":
        return "upgrade_head"
    if inspection.detected_state == "legacy_v1":
        return "stamp_baseline_then_upgrade"
    return "abort_unknown_database"


def inspect_database(database_url: str) -> DatabaseInspectionResult:
    """Inspect the target database and classify its migration state."""
    try:
        from sqlalchemy import create_engine, inspect
        from sqlalchemy.exc import SQLAlchemyError
    except ModuleNotFoundError as exc:
        raise MigrationBootstrapError(
            "SQLAlchemy is required to inspect the database. "
            "Install the backend dependencies before running this script."
        ) from exc

    try:
        engine = create_engine(database_url)
    except SQLAlchemyError as exc:
        raise MigrationBootstrapError(
            f"Unable to create SQLAlchemy engine from DATABASE_URL: {exc}"
        ) from exc

    try:
        with engine.connect() as connection:
            inspector = inspect(connection)
            public_tables = tuple(
                sorted(inspector.get_table_names(schema=PUBLIC_SCHEMA))
            )
            has_version_table = has_alembic_version_table(public_tables)
            current_revision = (
                read_current_revision(connection) if has_version_table else None
            )
            business_tables = tuple(
                table_name
                for table_name in public_tables
                if table_name != ALEMBIC_VERSION_TABLE
            )

            if has_version_table and current_revision:
                return DatabaseInspectionResult(
                    detected_state="alembic_versioned",
                    has_alembic_version_table=True,
                    current_revision=current_revision,
                    business_tables=business_tables,
                    is_empty=False,
                    matches_legacy_v1=False,
                )

            columns_by_table = {
                table_name: get_column_names(inspector, table_name)
                for table_name in LEGACY_V1_REQUIRED_COLUMNS
                if table_name in public_tables
            }
            empty_database = is_empty_database(public_tables)
            legacy_v1 = False
            if not empty_database:
                legacy_v1 = matches_legacy_v1_schema(
                    public_tables=public_tables,
                    columns_by_table=columns_by_table,
                )

            if empty_database:
                detected_state: DetectedState = "empty"
            elif legacy_v1:
                detected_state = "legacy_v1"
            else:
                detected_state = "unknown"

            return DatabaseInspectionResult(
                detected_state=detected_state,
                has_alembic_version_table=has_version_table,
                current_revision=current_revision,
                business_tables=business_tables,
                is_empty=empty_database,
                matches_legacy_v1=legacy_v1,
            )
    except SQLAlchemyError as exc:
        raise MigrationBootstrapError(
            f"Unable to inspect database state: {exc}"
        ) from exc
    finally:
        engine.dispose()


def read_current_revision(connection: Any) -> str | None:
    """Read the current Alembic revision if the version table is populated."""
    from sqlalchemy import text

    query = text(
        f"SELECT version_num FROM {PUBLIC_SCHEMA}.{ALEMBIC_VERSION_TABLE} LIMIT 1"
    )
    row = connection.execute(query).first()
    if row is None:
        return None

    version_num = row[0]
    if version_num is None:
        return None

    version_text = str(version_num).strip()
    return version_text or None


def get_column_names(inspector: Any, table_name: str) -> set[str]:
    """Return the set of public column names for a given table."""
    return {
        column_definition["name"]
        for column_definition in inspector.get_columns(
            table_name,
            schema=PUBLIC_SCHEMA,
        )
    }


@contextmanager
def temporary_alembic_config(
    *,
    repo_root: Path,
    database_url: str,
):
    """Create a temporary Alembic config file pointing to DATABASE_URL."""
    source_config_path = repo_root / "alembic.ini"
    if not source_config_path.exists():
        raise MigrationBootstrapError(
            f"Alembic configuration file not found: {source_config_path}"
        )

    parser = ConfigParser()
    parser.read(source_config_path)
    if not parser.has_section("alembic"):
        raise MigrationBootstrapError("Invalid alembic.ini: missing [alembic] section.")

    parser.set("alembic", "script_location", str(repo_root / "alembic"))
    parser.set("alembic", "sqlalchemy.url", database_url)

    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="alembic-bootstrap-",
        suffix=".ini",
        delete=False,
    ) as temp_file:
        parser.write(temp_file)
        temp_config_path = Path(temp_file.name)

    try:
        yield temp_config_path
    finally:
        temp_config_path.unlink(missing_ok=True)


def run_alembic_command(
    *,
    repo_root: Path,
    alembic_config_path: Path,
    arguments: list[str],
) -> None:
    """Run an Alembic CLI command with the temporary config."""
    command = ["alembic", "-c", str(alembic_config_path), *arguments]
    print(f"Running {' '.join(command)}")
    subprocess.run(command, cwd=repo_root, check=True)


def main() -> int:
    """Inspect the database and execute the matching Alembic bootstrap flow."""
    repo_root = Path(__file__).resolve().parents[1]
    database_url = require_database_url()
    wait_for_database(database_url)
    inspection = inspect_database(database_url)
    plan = resolve_migration_plan(inspection)

    print(f"Detected database state: {inspection.detected_state}")

    if inspection.has_alembic_version_table:
        if inspection.current_revision:
            print(
                "Alembic version table found: "
                f"current revision = {inspection.current_revision}"
            )
        else:
            print(
                "Alembic version table found but empty; "
                "treating database as non-versioned."
            )

    if inspection.detected_state == "empty":
        print("Empty database detected")
    elif inspection.detected_state == "legacy_v1":
        print("Legacy V1 database detected")

    if plan == "abort_unknown_database":
        raise MigrationBootstrapError(
            "Database is not empty, has no Alembic version, and does not match "
            "the expected V1 schema. Aborting."
        )

    with temporary_alembic_config(
        repo_root=repo_root,
        database_url=database_url,
    ) as alembic_config_path:
        if plan == "stamp_baseline_then_upgrade":
            baseline_revision = resolve_baseline_revision()
            print(f"Stamping baseline revision {baseline_revision}")
            run_alembic_command(
                repo_root=repo_root,
                alembic_config_path=alembic_config_path,
                arguments=["stamp", baseline_revision],
            )

        print("Running alembic upgrade head")
        run_alembic_command(
            repo_root=repo_root,
            alembic_config_path=alembic_config_path,
            arguments=["upgrade", "head"],
        )

    print("Migration completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
