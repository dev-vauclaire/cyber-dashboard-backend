"""Orchestration du scheduler : startup initial puis boucle périodique."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
import math
import time

from cyber_dashboard_scheduler.config import Settings
from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_database.repositories import SensorTypeRepository

from .collection_service import CollectionService
from .inventory_service import SourceInventoryService
from .retention_service import RetentionService

LOGGER = logging.getLogger(__name__)


class SchedulerRuntimeService:
    """Assemble le démarrage du scheduler puis sa boucle périodique."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: PostgresDatabase,
        inventory_service: SourceInventoryService,
        collection_service: CollectionService,
        retention_service: RetentionService,
    ) -> None:
        """Construit le service d'orchestration principal du scheduler."""
        self._settings = settings
        self._database = database
        self._inventory_service = inventory_service
        self._collection_service = collection_service
        self._retention_service = retention_service
        self._poll_interval_seconds = max(
            1,
            math.ceil(86400 / self._settings.limit_request_per_day),
        )

    def run_forever(self) -> None:
        """Exécute le démarrage complet puis la boucle infinie de collecte."""
        self._startup()

        cycle_number = 1
        while True:
            self._run_collection_cycle(cycle_number)
            cycle_number += 1
            LOGGER.info(
                "Attente de %s secondes avant le prochain cycle",
                self._poll_interval_seconds,
            )
            time.sleep(self._poll_interval_seconds)

    def _startup(self) -> None:
        """Effectue le bootstrap nécessaire avant d'entrer en boucle."""
        self._database.check_connection()

        sensor_types = self._load_sensor_types()
        LOGGER.info(
            "Types de capteurs chargés : %s",
            ", ".join(sensor_types) or "aucun",
        )
        LOGGER.info(
            "Boucle périodique configurée à un cycle toutes les %s secondes",
            self._poll_interval_seconds,
        )

    def _load_sensor_types(self) -> list[str]:
        """Charge les codes de types de capteurs au démarrage."""
        repository = SensorTypeRepository(self._database)
        return [str(row["code"]) for row in repository.list_sensor_types()]

    def _run_collection_cycle(self, cycle_number: int) -> None:
        """Lance un cycle complet : inventaire, collecte puis rétention."""
        started_at = datetime.now(UTC)
        LOGGER.info(
            "Début du cycle de collecte #%s à %s",
            cycle_number,
            started_at.isoformat(),
        )

        inventory_result = self._inventory_service.run_once()
        LOGGER.info(
            "Cycle #%s inventaire. configs_selectionnees=%s configs_ok=%s configs_ko=%s endpoints=%s persistes=%s desactivees=%s ignorees=%s erreurs=%s",
            cycle_number,
            inventory_result.configs_selected,
            inventory_result.configs_succeeded,
            inventory_result.configs_failed,
            ", ".join(inventory_result.endpoints_called) or "aucun",
            inventory_result.sources_persisted,
            inventory_result.sources_deactivated,
            inventory_result.sources_skipped,
            inventory_result.source_errors,
        )

        collection_result = self._collection_service.run_once()
        LOGGER.info(
            "Cycle #%s collecte. collecteurs=%s collecteurs_ok=%s collecteurs_ko=%s sources_traitees=%s attaques_lues=%s attaques_inserees=%s attaques_ignorees=%s",
            cycle_number,
            collection_result.collectors_selected,
            collection_result.collectors_succeeded,
            collection_result.collectors_failed,
            collection_result.sources_processed,
            collection_result.attacks_read,
            collection_result.attacks_inserted,
            collection_result.attacks_ignored,
        )

        retention_result = self._retention_service.run_once()
        LOGGER.info(
            "Cycle #%s retention. policies=%s policies_ok=%s policies_ko=%s lignes_supprimees=%s",
            cycle_number,
            retention_result.policies_selected,
            retention_result.policies_succeeded,
            retention_result.policies_failed,
            retention_result.rows_deleted,
        )

        ended_at = datetime.now(UTC)
        LOGGER.info(
            "Fin du cycle de collecte #%s à %s. collecteurs_ok=%s collecteurs_en_erreur=%s duree_cycle=%.2fs sources_traitees=%s attaques_lues=%s attaques_inserees=%s attaques_ignorees=%s policies_ok=%s policies_ko=%s lignes_supprimees=%s",
            cycle_number,
            ended_at.isoformat(),
            collection_result.collectors_succeeded,
            collection_result.collectors_failed,
            (ended_at - started_at).total_seconds(),
            collection_result.sources_processed,
            collection_result.attacks_read,
            collection_result.attacks_inserted,
            collection_result.attacks_ignored,
            retention_result.policies_succeeded,
            retention_result.policies_failed,
            retention_result.rows_deleted,
        )
