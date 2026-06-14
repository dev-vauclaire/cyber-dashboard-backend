"""Service d'orchestration des collectes d'attaques du scheduler."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Callable


LOGGER = logging.getLogger(__name__)
CollectionRunner = Callable[[], Any]


@dataclass(frozen=True, slots=True)
class CollectionRunResult:
    """Résumé d'un run de collecte."""

    collectors_selected: int = 0
    collectors_succeeded: int = 0
    collectors_failed: int = 0
    sources_processed: int = 0
    attacks_read: int = 0
    attacks_inserted: int = 0
    attacks_ignored: int = 0


class CollectionService:
    """Mutualise l'exécution des collecteurs d'attaques du scheduler."""

    def __init__(
        self,
        *,
        ogo_collection_runner: CollectionRunner | None = None,
        serenicity_sensor_collection_runner: CollectionRunner | None = None,
        lurio_collection_runner: CollectionRunner | None = None,
    ) -> None:
        self._runners: list[tuple[str, CollectionRunner]] = []
        if ogo_collection_runner is not None:
            self._runners.append(("OGO", ogo_collection_runner))
        if serenicity_sensor_collection_runner is not None:
            self._runners.append(("Detoxio", serenicity_sensor_collection_runner))
        if lurio_collection_runner is not None:
            self._runners.append(("Lurio", lurio_collection_runner))

    def run_once(self) -> CollectionRunResult:
        """Exécute une passe sur l'ensemble des collecteurs configurés."""
        if not self._runners:
            LOGGER.info(
                "Aucun collecteur d'attaques n'est encore activé pour ce run. "
                "Le scheduler reste limité à l'inventaire pour l'instant."
            )
            return CollectionRunResult()

        result = CollectionRunResult(collectors_selected=len(self._runners))
        for collector_name, collector in self._runners:
            try:
                collector_result = collector()
            except Exception as exc:
                result = self._with_collector_failure(result)
                LOGGER.exception(
                    "Échec du collecteur %s pendant le cycle courant : %s",
                    collector_name,
                    exc,
                )
                continue

            result = self._merge_result(
                left=result,
                right=self._extract_metrics(
                    collector_name=collector_name,
                    collector_result=collector_result,
                ),
            )

        return result

    @staticmethod
    def _with_collector_failure(result: CollectionRunResult) -> CollectionRunResult:
        return CollectionRunResult(
            collectors_selected=result.collectors_selected,
            collectors_succeeded=result.collectors_succeeded,
            collectors_failed=result.collectors_failed + 1,
            sources_processed=result.sources_processed,
            attacks_read=result.attacks_read,
            attacks_inserted=result.attacks_inserted,
            attacks_ignored=result.attacks_ignored,
        )

    @staticmethod
    def _merge_result(
        *,
        left: CollectionRunResult,
        right: CollectionRunResult,
    ) -> CollectionRunResult:
        return CollectionRunResult(
            collectors_selected=left.collectors_selected,
            collectors_succeeded=left.collectors_succeeded + right.collectors_succeeded,
            collectors_failed=left.collectors_failed + right.collectors_failed,
            sources_processed=left.sources_processed + right.sources_processed,
            attacks_read=left.attacks_read + right.attacks_read,
            attacks_inserted=left.attacks_inserted + right.attacks_inserted,
            attacks_ignored=left.attacks_ignored + right.attacks_ignored,
        )

    @staticmethod
    def _extract_metrics(
        *,
        collector_name: str,
        collector_result: Any,
    ) -> CollectionRunResult:
        sources_processed = getattr(collector_result, "sources_selected", None)
        if sources_processed is None:
            sources_processed = 1 if collector_name == "OGO" else 0

        attacks_read = 0
        for field_name in ("events_read", "fluxes_read", "reports_read"):
            field_value = getattr(collector_result, field_name, None)
            if field_value is not None:
                attacks_read = field_value
                break

        return CollectionRunResult(
            collectors_selected=0,
            collectors_succeeded=1,
            collectors_failed=0,
            sources_processed=int(sources_processed),
            attacks_read=attacks_read,
            attacks_inserted=int(
                getattr(
                    collector_result,
                    "events_inserted",
                    getattr(collector_result, "attacks_inserted", 0),
                )
            ),
            attacks_ignored=int(
                getattr(
                    collector_result,
                    "events_ignored",
                    getattr(collector_result, "attacks_ignored", 0),
                )
            ),
        )
