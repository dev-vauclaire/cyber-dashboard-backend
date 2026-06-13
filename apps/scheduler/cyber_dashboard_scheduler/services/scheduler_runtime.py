"""Orchestration du scheduler : startup initial puis boucle périodique."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import logging
import math
import time
from typing import Any, Callable

from cyber_dashboard_scheduler.config import Settings
from packages.database.db import PostgresDatabase
from packages.database.repositories import SensorTypeRepository

from .inventory import SourceInventoryService


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CycleMetrics:
    """Métriques consolidées d'un cycle de collecte.

    Attributes:
        sources_processed: Nombre de sources traitées pendant le cycle.
        attacks_read: Nombre total d'attaques ou événements lus.
        attacks_inserted: Nombre total d'attaques insérées.
        attacks_ignored: Nombre total d'attaques ignorées.
    """

    sources_processed: int = 0
    attacks_read: int = 0
    attacks_inserted: int = 0
    attacks_ignored: int = 0


class SchedulerRuntimeService:
    """Assemble le démarrage du scheduler puis sa boucle périodique."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: PostgresDatabase,
        inventory_service: SourceInventoryService,
        ogo_collection_runner: Callable[[], Any] | None,
        sensor_collection_runner: Callable[[], Any] | None,
        lurio_collection_runner: Callable[[], Any] | None,
    ) -> None:
        """Construit le service d'orchestration principal du scheduler.

        Args:
            settings: Configuration applicative.
            database: Accès PostgreSQL.
            inventory_service: Service d'inventaire initial.
            ogo_collection_runner: Callable lanceant la collecte OGO.
            sensor_collection_runner: Callable lanceant la collecte Serenicity capteurs.
            lurio_collection_runner: Callable lanceant la collecte Lurio.
        """
        self._settings = settings
        self._database = database
        self._inventory_service = inventory_service
        self._ogo_collection_runner = ogo_collection_runner
        self._sensor_collection_runner = sensor_collection_runner
        self._lurio_collection_runner = lurio_collection_runner
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

        inventory_result = self._inventory_service.run_once()
        LOGGER.info(
            "Inventaire initial terminé. configs_selectionnees=%s configs_ok=%s configs_ko=%s endpoints=%s persistes=%s desactivees=%s ignorees=%s erreurs=%s",
            inventory_result.configs_selected,
            inventory_result.configs_succeeded,
            inventory_result.configs_failed,
            ", ".join(inventory_result.endpoints_called) or "aucun",
            inventory_result.sources_persisted,
            inventory_result.sources_deactivated,
            inventory_result.sources_skipped,
            inventory_result.source_errors,
        )

    def _load_sensor_types(self) -> list[str]:
        """Charge les codes de types de capteurs au démarrage."""
        repository = SensorTypeRepository(self._database)
        return [str(row["code"]) for row in repository.list_sensor_types()]

    def _run_collection_cycle(self, cycle_number: int) -> None:
        """Lance un cycle de collecte complet en isolant les erreurs par collecteur."""
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

        collectors_succeeded = 0
        collectors_failed = 0
        metrics = CycleMetrics()

        collectors: list[tuple[str, Any]] = []
        if self._ogo_collection_runner is not None:
            collectors.append(("OGO", self._ogo_collection_runner))
        if self._sensor_collection_runner is not None:
            collectors.append(("Detoxio", self._sensor_collection_runner))
        if self._lurio_collection_runner is not None:
            collectors.append(("Lurio", self._lurio_collection_runner))

        if not collectors:
            LOGGER.info(
                "Aucun collecteur d'attaques n'est encore activé pour ce run. "
                "Le scheduler reste limité à l'inventaire pour l'instant."
            )
            return

        for collector_name, collector in collectors:
            try:
                collector_result = collector()
                collectors_succeeded += 1
                metrics = self._merge_cycle_metrics(
                    metrics,
                    self._extract_cycle_metrics(
                        collector_name=collector_name,
                        collector_result=collector_result,
                    ),
                )
            except Exception as exc:
                collectors_failed += 1
                LOGGER.exception(
                    "Échec du collecteur %s pendant le cycle #%s : %s",
                    collector_name,
                    cycle_number,
                    exc,
                )

        ended_at = datetime.now(UTC)
        LOGGER.info(
            "Fin du cycle de collecte #%s à %s. collecteurs_ok=%s collecteurs_en_erreur=%s duree_cycle=%.2fs sources_traitees=%s attaques_lues=%s attaques_inserees=%s attaques_ignorees=%s",
            cycle_number,
            ended_at.isoformat(),
            collectors_succeeded,
            collectors_failed,
            (ended_at - started_at).total_seconds(),
            metrics.sources_processed,
            metrics.attacks_read,
            metrics.attacks_inserted,
            metrics.attacks_ignored,
        )

    @staticmethod
    def _merge_cycle_metrics(left: CycleMetrics, right: CycleMetrics) -> CycleMetrics:
        """Additionne deux jeux de métriques de cycle.

        Args:
            left: Premier jeu de métriques.
            right: Second jeu de métriques.

        Returns:
            Les métriques cumulées.
        """
        return CycleMetrics(
            sources_processed=left.sources_processed + right.sources_processed,
            attacks_read=left.attacks_read + right.attacks_read,
            attacks_inserted=left.attacks_inserted + right.attacks_inserted,
            attacks_ignored=left.attacks_ignored + right.attacks_ignored,
        )

    @staticmethod
    def _extract_cycle_metrics(*, collector_name: str, collector_result: Any) -> CycleMetrics:
        """Projette le résultat d'un collecteur vers un format de métriques commun.

        Args:
            collector_name: Nom du collecteur pour les collecteurs mono-source.
            collector_result: Dataclass résultat renvoyée par le collecteur.

        Returns:
            Les métriques consolidées exploitables au niveau d'un cycle.
        """
        sources_processed = getattr(collector_result, "sources_selected", None)
        if sources_processed is None:
            sources_processed = 1 if collector_name == "OGO" else 0

        attacks_read = 0
        for field_name in ("events_read", "fluxes_read", "reports_read"):
            field_value = getattr(collector_result, field_name, None)
            if field_value is not None:
                attacks_read = field_value
                break

        return CycleMetrics(
            sources_processed=sources_processed,
            attacks_read=attacks_read,
            attacks_inserted=getattr(
                collector_result,
                "events_inserted",
                getattr(collector_result, "attacks_inserted", 0),
            ),
            attacks_ignored=getattr(
                collector_result,
                "events_ignored",
                getattr(collector_result, "attacks_ignored", 0),
            ),
        )
