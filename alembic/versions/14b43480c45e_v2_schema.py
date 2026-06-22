"""v2 schema

Revision ID: 14b43480c45e
Revises: 6d98af97a0e5
Create Date: 2026-06-10 16:50:08.078903

"""

from __future__ import annotations

import os
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

from packages.common.secret_service import SecretConfigurationError, SecretService


# revision identifiers, used by Alembic.
revision: str = '14b43480c45e'
down_revision: Union[str, Sequence[str], None] = '6d98af97a0e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


LEGACY_OGO_CONFIG_NAME = "legacy-ogo"
LEGACY_SERENICITY_CONFIG_NAME = "legacy-serenicity"


class _MigrationSecretSettings:
    """Minimal secret settings used during migration."""

    def __init__(self, secret_key_file: str | None, secret_key: str | None) -> None:
        self.secret_key_file = secret_key_file
        self.secret_key = secret_key


def _get_optional_env(name: str) -> str | None:
    """Return a trimmed optional environment variable."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _build_secret_service() -> SecretService:
    """Instantiate the shared secret service with migration env settings."""
    return SecretService(
        _MigrationSecretSettings(
            secret_key_file=_get_optional_env("CYBER_DASHBOARD_SECRET_KEY_FILE"),
            secret_key=_get_optional_env("CYBER_DASHBOARD_SECRET_KEY"),
        )
    )


def _backfill_specialized_sources() -> None:
    """Redistribute legacy V1 source data into specialized V2 tables."""
    if not context.is_offline_mode():
        bind = op.get_bind()

        duplicate_ogo_domain_name = bind.execute(
            sa.text(
                """
                SELECT BTRIM(s.external_id) AS domain_name
                FROM sources AS s
                JOIN sensor_types AS st
                    ON st.id = s.sensor_type_id
                WHERE s.external_id IS NOT NULL
                  AND BTRIM(s.external_id) <> ''
                  AND st.code = 'waf'
                GROUP BY BTRIM(s.external_id)
                HAVING COUNT(*) > 1
                LIMIT 1
                """
            )
        ).scalar_one_or_none()
        if duplicate_ogo_domain_name is not None:
            raise RuntimeError(
                "Migration V2 cannot continue because duplicate OGO domain_name values "
                f"were found in V1 sources: {duplicate_ogo_domain_name}"
            )

        duplicate_serenicity_external_id = bind.execute(
            sa.text(
                """
                SELECT BTRIM(s.external_id) AS external_id
                FROM sources AS s
                JOIN sensor_types AS st
                    ON st.id = s.sensor_type_id
                WHERE s.external_id IS NOT NULL
                  AND BTRIM(s.external_id) <> ''
                  AND st.code IN ('lurio', 'detoxio')
                  AND s.external_id ~ '^[0-9]+$'
                GROUP BY BTRIM(s.external_id)
                HAVING COUNT(*) > 1
                LIMIT 1
                """
            )
        ).scalar_one_or_none()
        if duplicate_serenicity_external_id is not None:
            raise RuntimeError(
                "Migration V2 cannot continue because duplicate Serenicity "
                "external_id values were found in V1 sources: "
                f"{duplicate_serenicity_external_id}"
            )

    op.execute(
        """
        INSERT INTO serenicity_sources (
            source_id,
            external_id,
            latitude,
            longitude
        )
        SELECT
            s.id,
            s.external_id,
            s.latitude,
            s.longitude
        FROM sources AS s
        JOIN sensor_types AS st
            ON st.id = s.sensor_type_id
        WHERE s.external_id IS NOT NULL
          AND BTRIM(s.external_id) <> ''
          AND st.code IN ('lurio', 'detoxio')
          AND s.external_id ~ '^[0-9]+$'
        ON CONFLICT (source_id) DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO ogo_sources (
            source_id,
            domain_name,
            organization_codes
        )
        SELECT
            s.id,
            s.external_id,
            ARRAY[]::VARCHAR[]
        FROM sources AS s
        JOIN sensor_types AS st
            ON st.id = s.sensor_type_id
        WHERE s.external_id IS NOT NULL
          AND BTRIM(s.external_id) <> ''
          AND st.code = 'waf'
        ON CONFLICT (source_id) DO NOTHING
        """
    )
    op.execute("UPDATE sources SET updated_at = created_at, is_active = FALSE")


def _insert_legacy_collector_config(
    *,
    bind: sa.engine.Connection,
    name: str,
    collector_type: str,
    encrypted_email: str | None,
    email_hint: str | None,
    encrypted_api_key: str | None,
    api_key_hint: str | None,
) -> None:
    """Create a collector config inherited from legacy environment variables."""
    bind.execute(
        sa.text(
            """
            INSERT INTO attacks_collector_config (
                name,
                collector_type,
                encrypted_email,
                email_hint,
                encrypted_api_key,
                api_key_hint,
                is_active,
                last_validation_status
            )
            VALUES (
                :name,
                :collector_type,
                :encrypted_email,
                :email_hint,
                :encrypted_api_key,
                :api_key_hint,
                TRUE,
                'not_tested'
            )
            ON CONFLICT (collector_type, name) DO NOTHING
            """
        ),
        {
            "name": name,
            "collector_type": collector_type,
            "encrypted_email": encrypted_email,
            "email_hint": email_hint,
            "encrypted_api_key": encrypted_api_key,
            "api_key_hint": api_key_hint,
        },
    )


def _attach_specialized_sources_to_config(
    *,
    bind: sa.engine.Connection,
    collector_type: str,
    config_name: str,
    specialized_table: str,
) -> None:
    """Attach migrated specialized sources to the matching legacy config."""
    bind.execute(
        sa.text(
            f"""
            UPDATE sources AS s
            SET attacks_collector_config_id = config.id
            FROM {specialized_table} AS specialized
            INNER JOIN attacks_collector_config AS config
                ON config.collector_type = :collector_type
               AND config.name = :config_name
            WHERE s.id = specialized.source_id
              AND s.attacks_collector_config_id IS NULL
            """
        ),
        {
            "collector_type": collector_type,
            "config_name": config_name,
        },
    )


def _backfill_legacy_collector_configs() -> None:
    """Create legacy attack collector configs from environment variables."""
    if context.is_offline_mode():
        return

    ogo_username = _get_optional_env("OGO_USERNAME")
    ogo_api_key = _get_optional_env("OGO_API_KEY")
    serenicity_api_key = _get_optional_env("SERENICITY_API_KEY")

    if bool(ogo_username) != bool(ogo_api_key):
        raise RuntimeError(
            "Legacy OGO migration requires both OGO_USERNAME and OGO_API_KEY "
            "when one of them is provided."
        )

    if not any((ogo_username, ogo_api_key, serenicity_api_key)):
        return

    try:
        secret_service = _build_secret_service()
    except SecretConfigurationError as exc:
        raise RuntimeError(
            "Legacy collector config migration requires a valid "
            "CYBER_DASHBOARD_SECRET_KEY_FILE or CYBER_DASHBOARD_SECRET_KEY "
            "when legacy credentials are present."
        ) from exc

    bind = op.get_bind()

    if ogo_username and ogo_api_key:
        _insert_legacy_collector_config(
            bind=bind,
            name=LEGACY_OGO_CONFIG_NAME,
            collector_type="ogo",
            encrypted_email=secret_service.encrypt_secret(ogo_username),
            email_hint=secret_service.build_secret_hint(ogo_username),
            encrypted_api_key=secret_service.encrypt_secret(ogo_api_key),
            api_key_hint=secret_service.build_secret_hint(ogo_api_key),
        )
        _attach_specialized_sources_to_config(
            bind=bind,
            collector_type="ogo",
            config_name=LEGACY_OGO_CONFIG_NAME,
            specialized_table="ogo_sources",
        )

    if serenicity_api_key:
        _insert_legacy_collector_config(
            bind=bind,
            name=LEGACY_SERENICITY_CONFIG_NAME,
            collector_type="serenicity",
            encrypted_email=None,
            email_hint=None,
            encrypted_api_key=secret_service.encrypt_secret(serenicity_api_key),
            api_key_hint=secret_service.build_secret_hint(serenicity_api_key),
        )
        _attach_specialized_sources_to_config(
            bind=bind,
            collector_type="serenicity",
            config_name=LEGACY_SERENICITY_CONFIG_NAME,
            specialized_table="serenicity_sources",
        )


def _migrate_scheduler_state() -> None:
    """Split legacy scheduler state fields into inventory and collection fields."""
    op.add_column(
        "scheduler_state",
        sa.Column(
            "last_inventory_status",
            sa.String(length=30),
            server_default=sa.text("'not_run'"),
            nullable=False,
        ),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_inventory_success_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_inventory_error_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_inventory_error_message", sa.Text(), nullable=True),
    )
    op.add_column(
        "scheduler_state",
        sa.Column(
            "last_collection_status",
            sa.String(length=30),
            server_default=sa.text("'not_run'"),
            nullable=False,
        ),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_collection_success_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_collection_error_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_collection_error_message", sa.Text(), nullable=True),
    )
    op.create_check_constraint(
        "scheduler_state_last_inventory_status_check",
        "scheduler_state",
        "last_inventory_status IN ('not_run', 'success', 'failed')",
    )
    op.create_check_constraint(
        "scheduler_state_last_collection_status_check",
        "scheduler_state",
        "last_collection_status IN ('not_run', 'success', 'failed')",
    )

    op.execute(
        """
        UPDATE scheduler_state
        SET
            last_inventory_status = CASE
                WHEN last_inventory_at IS NULL THEN 'not_run'
                ELSE 'success'
            END,
            last_inventory_success_at = last_inventory_at,
            last_inventory_error_at = NULL,
            last_inventory_error_message = NULL,
            last_collection_status = CASE
                WHEN last_poll_at IS NULL THEN 'not_run'
                WHEN last_error_at IS NOT NULL
                     AND (last_success_at IS NULL OR last_error_at >= last_success_at)
                THEN 'failed'
                ELSE 'success'
            END,
            last_collection_success_at = CASE
                WHEN last_poll_at IS NULL THEN NULL
                WHEN last_success_at IS NOT NULL THEN last_success_at
                ELSE last_poll_at
            END,
            last_collection_error_at = CASE
                WHEN last_poll_at IS NOT NULL
                     AND last_error_at IS NOT NULL
                     AND (last_success_at IS NULL OR last_error_at >= last_success_at)
                THEN last_error_at
                ELSE NULL
            END,
            last_collection_error_message = CASE
                WHEN last_poll_at IS NOT NULL
                     AND last_error_at IS NOT NULL
                     AND (last_success_at IS NULL OR last_error_at >= last_success_at)
                THEN last_error_message
                ELSE NULL
            END
        """
    )

    op.drop_column("scheduler_state", "last_error_message")
    op.drop_column("scheduler_state", "last_error_at")
    op.drop_column("scheduler_state", "last_success_at")


def _restore_legacy_scheduler_state() -> None:
    """Rebuild the V1 scheduler state fields from V2 inventory/collection fields."""
    op.add_column(
        "scheduler_state",
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scheduler_state",
        sa.Column("last_error_message", sa.Text(), nullable=True),
    )

    op.execute(
        """
        UPDATE scheduler_state
        SET
            last_success_at = COALESCE(
                last_collection_success_at,
                last_inventory_success_at
            ),
            last_error_at = COALESCE(
                last_collection_error_at,
                last_inventory_error_at
            ),
            last_error_message = COALESCE(
                last_collection_error_message,
                last_inventory_error_message
            )
        """
    )

    op.drop_constraint(
        "scheduler_state_last_collection_status_check",
        "scheduler_state",
        type_="check",
    )
    op.drop_constraint(
        "scheduler_state_last_inventory_status_check",
        "scheduler_state",
        type_="check",
    )
    op.drop_column("scheduler_state", "last_collection_error_message")
    op.drop_column("scheduler_state", "last_collection_error_at")
    op.drop_column("scheduler_state", "last_collection_success_at")
    op.drop_column("scheduler_state", "last_collection_status")
    op.drop_column("scheduler_state", "last_inventory_error_message")
    op.drop_column("scheduler_state", "last_inventory_error_at")
    op.drop_column("scheduler_state", "last_inventory_success_at")
    op.drop_column("scheduler_state", "last_inventory_status")


def upgrade() -> None:
    """Upgrade schema."""

    op.create_table(
        "attacks_collector_config",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=30), nullable=False),
        sa.Column(
            "collector_type",
            sa.Enum("ogo", "serenicity", name="attacks_collector_type"),
            nullable=False,
        ),
        sa.Column("encrypted_email", sa.String(length=255), nullable=True),
        sa.Column("email_hint", sa.String(length=32), nullable=True),
        sa.Column("encrypted_api_key", sa.Text(), nullable=True),
        sa.Column("api_key_hint", sa.String(length=32), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("FALSE"),
            nullable=False,
        ),
        sa.Column(
            "inventory_requested",
            sa.Boolean(),
            server_default=sa.text("TRUE"),
            nullable=False,
        ),
        sa.Column("last_validation_status", sa.String(length=30), nullable=True),
        sa.Column("last_validation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_validation_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "last_validation_status IS NULL OR last_validation_status IN "
            "('success', 'failed', 'not_tested')",
            name="attacks_collector_config_validation_status_check",
        ),
        sa.CheckConstraint(
            "LENGTH(TRIM(name)) > 0",
            name="attacks_collector_config_name_not_empty",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "collector_type",
            "encrypted_email",
            "encrypted_api_key",
            name="attacks_collector_config_unique_email_api_key_per_type",
        ),
    )
    op.create_table(
        "cti_config",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False),
        sa.Column("label", sa.String(length=150), nullable=False),
        sa.Column("encrypted_api_key", sa.Text(), nullable=True),
        sa.Column("api_key_hint", sa.String(length=32), nullable=True),
        sa.Column(
            "is_key_required",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=True,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("FALSE"),
            nullable=False,
        ),
        sa.Column("last_validation_status", sa.String(length=30), nullable=True),
        sa.Column("last_validation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_validation_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "last_validation_status IS NULL OR last_validation_status IN "
            "('success', 'failed', 'not_tested')",
            name="cti_config_validation_status_check",
        ),
        sa.CheckConstraint(
            "LENGTH(TRIM(code)) > 0",
            name="cti_config_code_not_empty",
        ),
        sa.CheckConstraint(
            "LENGTH(TRIM(label)) > 0",
            name="cti_config_label_not_empty",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )
    op.execute(
        """
        INSERT INTO cti_config (
            code,
            label,
            is_key_required,
            is_active,
            last_validation_status
        )
        VALUES
            ('abuseipdb', 'AbuseIPDB', TRUE, FALSE, 'not_tested'),
            ('ipdata', 'IPData', TRUE, FALSE, 'not_tested'),
            ('greynoise', 'GreyNoise', TRUE, FALSE, 'not_tested'),
            ('virustotal', 'VirusTotal', TRUE, FALSE, 'not_tested'),
            ('shodan', 'Shodan', TRUE, FALSE, 'not_tested'),
            ('rdap', 'RDAP / WHOIS', FALSE, FALSE, 'not_tested'),
            ('reverse_dns', 'Reverse DNS', FALSE, FALSE, 'not_tested')
        ON CONFLICT (code) DO NOTHING
        """
    )
    op.create_table(
        "smtp_config",
        sa.Column("id", sa.SmallInteger(), server_default=sa.text("1"), nullable=False),
        sa.Column("smtp_host", sa.String(length=255), nullable=True),
        sa.Column("smtp_port", sa.Integer(), nullable=True),
        sa.Column("smtp_user", sa.String(length=255), nullable=True),
        sa.Column("encrypted_smtp_password", sa.Text(), nullable=True),
        sa.Column("smtp_password_hint", sa.String(length=32), nullable=True),
        sa.Column("smtp_from", sa.String(length=255), nullable=True),
        sa.Column("smtp_from_name", sa.String(length=255), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("FALSE"),
            nullable=False,
        ),
        sa.Column("last_validation_status", sa.String(length=30), nullable=True),
        sa.Column("last_validation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_validation_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "last_validation_status IS NULL OR last_validation_status IN "
            "('success', 'failed', 'not_tested')",
            name="smtp_config_validation_status_check",
        ),
        sa.CheckConstraint("id = 1", name="smtp_config_singleton"),
        sa.CheckConstraint(
            "smtp_port IS NULL OR smtp_port BETWEEN 1 AND 65535",
            name="smtp_config_port_range",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    """ Initialisation de la config smtp """
    op.execute(
        """
        INSERT INTO smtp_config (
            id,
            smtp_host,
            smtp_port,
            smtp_user,
            encrypted_smtp_password,
            smtp_password_hint,
            smtp_from,
            smtp_from_name,
            is_active,
            last_validation_status
        )
        VALUES
            (1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, 'not_tested')
        ON CONFLICT (id) DO NOTHING
        """
    )

    op.create_table(
        "ogo_sources",
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("domain_name", sa.String(length=500), nullable=False),
        sa.Column(
            "organization_codes",
            sa.ARRAY(sa.String(length=100)),
            server_default=sa.text("'{}'::character varying[]"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "LENGTH(TRIM(domain_name)) > 0",
            name="ogo_sources_domain_name_not_empty",
        ),
        sa.UniqueConstraint("domain_name", name="ogo_sources_domain_name_unique"),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("source_id"),
    )
    op.create_table(
        "serenicity_sources",
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.CheckConstraint(
            "LENGTH(TRIM(external_id)) > 0",
            name="serenicity_sources_external_id_not_empty",
        ),
        sa.CheckConstraint(
            "latitude IS NULL OR latitude BETWEEN -90 AND 90",
            name="serenicity_sources_latitude_range",
        ),
        sa.CheckConstraint(
            "longitude IS NULL OR longitude BETWEEN -180 AND 180",
            name="serenicity_sources_longitude_range",
        ),
        sa.UniqueConstraint(
            "external_id",
            name="serenicity_sources_external_id_unique",
        ),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("source_id"),
    )
    op.drop_index(op.f("idx_attacks_attacker_ip"), table_name="attacks")
    op.drop_index(op.f("idx_attacks_occurred_at"), table_name="attacks")
    op.drop_index(
        op.f("idx_attacks_pending_occurred_at"),
        table_name="attacks",
        postgresql_where="(correlation_status = 'pending'::status_correlation)",
    )
    op.drop_index(op.f("idx_attacks_source_occurred_at"), table_name="attacks")
    op.drop_index(
        op.f("idx_attacks_type_occurred_at"),
        table_name="attacks",
        postgresql_where="(attack_type IS NOT NULL)",
    )
    op.add_column(
        "sources",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.add_column(
        "sources",
        sa.Column("attacks_collector_config_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "sources_attacks_collector_config_id_fkey",
        "sources",
        "attacks_collector_config",
        ["attacks_collector_config_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.alter_column(
        "sources",
        "color",
        existing_type=sa.VARCHAR(length=7),
        type_=sa.String(length=30),
        nullable=True,
        server_default=None,
        existing_server_default=sa.text("'#FF0000'::character varying"),
    )
    op.drop_index(op.f("idx_sources_sensor_type_id"), table_name="sources")
    op.drop_constraint(
        op.f("sources_sensor_type_id_external_id_key"),
        "sources",
        type_="unique",
    )
    op.create_check_constraint(
        "sources_name_not_empty",
        "sources",
        "LENGTH(TRIM(name)) > 0",
    )
    """ Rempli les sources spécialisées ogo et serenicity à partir des données de la table sources """
    _backfill_specialized_sources()
    """ Crée les configs d'attaque à partir des variables d'env correspondantes pour les sources migrées"""
    _backfill_legacy_collector_configs()
    """ Aligne scheduler_state sur la séparation inventaire / collecte """
    _migrate_scheduler_state()

    op.drop_column("sources", "external_id")
    op.drop_column("sources", "longitude")
    op.drop_column("sources", "latitude")

    op.create_table(
        "retention_policies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_table", sa.String(length=50), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("FALSE"),
            nullable=False,
        ),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_deleted_count", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "target_table IN ('attacks', 'common_ip_alerts')",
            name="retention_policies_target_table_check",
        ),
        sa.CheckConstraint(
            "retention_days > 0",
            name="retention_policies_retention_days_positive",
        ),
        sa.CheckConstraint(
            "last_deleted_count IS NULL OR last_deleted_count >= 0",
            name="retention_policies_last_deleted_count_non_negative",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "target_table",
            name="retention_policies_target_table_unique",
        ),
    )
    op.execute(
        """
        INSERT INTO retention_policies (
            target_table,
            retention_days,
            is_active
        )
        VALUES
            ('attacks', 365, TRUE),
            ('common_ip_alerts', 365, TRUE)
        ON CONFLICT (target_table) DO NOTHING
        """
    )

def downgrade() -> None:
    """Downgrade schema."""
   

    op.add_column(
        "sources",
        sa.Column(
            "latitude",
            sa.DOUBLE_PRECISION(precision=53),
            autoincrement=False,
            nullable=True,
        ),
    )
    op.add_column(
        "sources",
        sa.Column(
            "longitude",
            sa.DOUBLE_PRECISION(precision=53),
            autoincrement=False,
            nullable=True,
        ),
    )
    op.add_column(
        "sources",
        sa.Column(
            "external_id",
            sa.VARCHAR(length=150),
            autoincrement=False,
            nullable=True,
        ),
    )
    op.execute(
        """
        UPDATE sources AS s
        SET
            external_id = ss.external_id,
            latitude = ss.latitude,
            longitude = ss.longitude
        FROM serenicity_sources AS ss
        WHERE s.id = ss.source_id
        """
    )
    op.execute(
        """
        UPDATE sources AS s
        SET external_id = os.domain_name
        FROM ogo_sources AS os
        WHERE s.id = os.source_id
        """
    )
    _restore_legacy_scheduler_state()
    op.drop_constraint("sources_name_not_empty", "sources", type_="check")
    op.create_unique_constraint(
        op.f("sources_sensor_type_id_external_id_key"),
        "sources",
        ["sensor_type_id", "external_id"],
    )
    op.create_index(
        op.f("idx_sources_sensor_type_id"),
        "sources",
        ["sensor_type_id"],
        unique=False,
    )
    op.execute(
        """
        UPDATE sources
        SET color = '#FF0000'
        WHERE color IS NULL
           OR BTRIM(color) = ''
           OR LENGTH(color) > 7
        """
    )
    op.alter_column(
        "sources",
        "color",
        existing_type=sa.String(length=30),
        type_=sa.VARCHAR(length=7),
        nullable=False,
        server_default=sa.text("'#FF0000'"),
        existing_server_default=None,
    )
    op.drop_column("sources", "updated_at")
    op.create_index(
        op.f("idx_attacks_type_occurred_at"),
        "attacks",
        ["attack_type", sa.literal_column("occurred_at DESC")],
        unique=False,
        postgresql_where="(attack_type IS NOT NULL)",
    )
    op.create_index(
        op.f("idx_attacks_source_occurred_at"),
        "attacks",
        ["source_id", sa.literal_column("occurred_at DESC")],
        unique=False,
    )
    op.create_index(
        op.f("idx_attacks_pending_occurred_at"),
        "attacks",
        ["occurred_at", "id"],
        unique=False,
        postgresql_where="(correlation_status = 'pending'::status_correlation)",
    )
    op.create_index(
        op.f("idx_attacks_occurred_at"),
        "attacks",
        [sa.literal_column("occurred_at DESC")],
        unique=False,
    )
    op.create_index(
        op.f("idx_attacks_attacker_ip"),
        "attacks",
        ["attacker_ip"],
        unique=False,
    )
    op.drop_constraint(
        "sources_attacks_collector_config_id_fkey",
        "sources",
        type_="foreignkey",
    )
    op.drop_column("sources", "attacks_collector_config_id")
    op.drop_table("serenicity_sources")
    op.drop_table("ogo_sources")
    op.drop_table("smtp_config")
    op.drop_table("cti_config")
    op.drop_table("attacks_collector_config")
    op.execute("DROP TYPE IF EXISTS attacks_collector_type")
    op.drop_table("retention_policies")
