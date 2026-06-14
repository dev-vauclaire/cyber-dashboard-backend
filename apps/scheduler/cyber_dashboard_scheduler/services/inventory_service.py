"""Service d'orchestration de l'inventaire des sources."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging

from packages.common.secret_service import SecretService
from packages.database.repositories import (
    AttacksCollectorConfigRepository,
    SchedulerStateRepository,
    SensorTypeRepository,
    SourceRepository,
)

from cyber_dashboard_scheduler.clients import OgoApiClient
from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_scheduler.services.inventory import (
    OgoInventoryService,
    SerenicityInventoryService,
    SerenicityLurioClientFactory,
    SerenicitySensorClientFactory,
)
from cyber_dashboard_scheduler.services.inventory.common import (
    build_current_sources_by_key,
    deactivate_missing_sources,
)


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class InventoryRunResult:
    """Résumé d'un run d'inventaire."""

    configs_selected: int = 0
    configs_succeeded: int = 0
    configs_failed: int = 0
    endpoints_called: list[str] = field(default_factory=list)
    sources_detected: int = 0
    sources_persisted: int = 0
    sources_deactivated: int = 0
    sources_skipped: int = 0
    source_errors: int = 0


class SourceInventoryService:
    """Orchestre l'inventaire des sources à partir des configurations actives."""

    def __init__(
        self,
        *,
        database: PostgresDatabase,
        secret_service: SecretService,
        ogo_client: OgoApiClient,
        serenicity_sensor_client_factory: SerenicitySensorClientFactory,
        serenicity_lurio_client_factory: SerenicityLurioClientFactory,
    ) -> None:
        self._config_repository = AttacksCollectorConfigRepository(database)
        self._sensor_type_repository = SensorTypeRepository(database)
        self._source_repository = SourceRepository(database)
        self._scheduler_state_repository = SchedulerStateRepository(database)
        self._ogo_inventory_service = OgoInventoryService(
            database=database,
            secret_service=secret_service,
            ogo_client=ogo_client,
        )
        self._serenicity_inventory_service = SerenicityInventoryService(
            database=database,
            secret_service=secret_service,
            serenicity_sensor_client_factory=serenicity_sensor_client_factory,
            serenicity_lurio_client_factory=serenicity_lurio_client_factory,
        )

    def run_once(self) -> InventoryRunResult:
        """Exécute un inventaire complet des configurations demandées."""
        inventory_timestamp = datetime.now(UTC)
        result = InventoryRunResult()
        sensor_type_colors = self._load_sensor_type_colors()
        configs = self._config_repository.list_active_inventory_requested_configs()
        result.configs_selected = len(configs)

        LOGGER.info(
            "Début de l'inventaire scheduler. configs_selectionnees=%s types_supportes=%s",
            result.configs_selected,
            ", ".join(sorted(sensor_type_colors)) or "aucun",
        )

        for config in configs:
            collector_type = str(config["collector_type"])
            config_id = int(config["id"])
            current_sources = self._source_repository.list_sources_for_inventory(
                config_id=config_id
            )
            current_sources_by_key = build_current_sources_by_key(current_sources)

            LOGGER.info(
                "Inventaire de la configuration id=%s type=%s name=%s",
                config_id,
                collector_type,
                config["name"],
            )

            if collector_type == "ogo":
                outcome = self._ogo_inventory_service.run_config(
                    config=config,
                    sensor_type_colors=sensor_type_colors,
                    current_sources_by_key=current_sources_by_key,
                    inventory_timestamp=inventory_timestamp,
                    result=result,
                )
            elif collector_type == "serenicity":
                outcome = self._serenicity_inventory_service.run_config(
                    config=config,
                    sensor_type_colors=sensor_type_colors,
                    current_sources_by_key=current_sources_by_key,
                    inventory_timestamp=inventory_timestamp,
                    result=result,
                )
            else:
                LOGGER.error(
                    "Type de collecteur non supporté pour l'inventaire id=%s type=%s",
                    config_id,
                    collector_type,
                )
                outcome = None

            if outcome is None:
                is_success = False
            else:
                had_deactivation_error = deactivate_missing_sources(
                    logger=LOGGER,
                    source_repository=self._source_repository,
                    scheduler_state_repository=self._scheduler_state_repository,
                    config_id=config_id,
                    current_sources_by_key=current_sources_by_key,
                    seen_source_keys=outcome.seen_source_keys,
                    inventory_timestamp=inventory_timestamp,
                    result=result,
                )
                is_success = not (outcome.had_error or had_deactivation_error)

            if is_success:
                self._config_repository.clear_inventory_request(config_id=config_id)
                result.configs_succeeded += 1
                LOGGER.info(
                    "Inventaire terminé avec succès pour la configuration id=%s",
                    config_id,
                )
            else:
                result.configs_failed += 1
                LOGGER.warning(
                    "Inventaire partiel ou en erreur pour la configuration id=%s. "
                    "inventory_requested reste à TRUE pour un retry futur.",
                    config_id,
                )

        LOGGER.info(
            "Inventaire scheduler terminé. configs_ok=%s configs_ko=%s detectees=%s persistees=%s desactivees=%s ignorees=%s erreurs=%s",
            result.configs_succeeded,
            result.configs_failed,
            result.sources_detected,
            result.sources_persisted,
            result.sources_deactivated,
            result.sources_skipped,
            result.source_errors,
        )
        return result

    def _load_sensor_type_colors(self) -> dict[str, str]:
        rows = self._sensor_type_repository.list_sensor_types()
        return {
            str(row["code"]): str(row["color"])
            for row in rows
            if row.get("code") is not None and row.get("color") is not None
        }
