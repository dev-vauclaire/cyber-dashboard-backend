from __future__ import annotations

import logging
import time
from typing import Callable


class BatchProcessingTimeTracker:
    # Responsabilite : mesurer et journaliser le temps moyen de traitement des attaques d'un lot.

    def __init__(
        self,
        *,
        enabled: bool,
        perf_counter_fn: Callable[[], float] = time.perf_counter,
    ) -> None:
        # Initialiser le suivi de performance d'un lot.
        self._enabled = enabled
        self._perf_counter_fn = perf_counter_fn
        self._processed_attack_count = 0
        self._total_processing_time_seconds = 0.0

    @property
    def processed_attack_count(self) -> int:
        # Exposer le nombre d'attaques mesurees dans le lot.
        return self._processed_attack_count

    @property
    def total_processing_time_seconds(self) -> float:
        # Exposer le temps cumule mesure dans le lot.
        return self._total_processing_time_seconds

    def start_attack(self) -> float | None:
        # Demarrer la mesure d'une attaque si le suivi est active.
        if not self._enabled:
            return None
        return self._perf_counter_fn()

    def record_completed_attack(self, start_time: float | None) -> None:
        # Enregistrer le temps d'une attaque terminee avec succes.
        if start_time is None:
            return

        elapsed_seconds = self._perf_counter_fn() - start_time
        self._processed_attack_count += 1
        self._total_processing_time_seconds += elapsed_seconds

    def log_batch_average(self, logger: logging.Logger) -> None:
        # Journaliser le temps moyen du lot si au moins une attaque a ete mesuree.
        if self._processed_attack_count == 0:
            return

        average_seconds = (
            self._total_processing_time_seconds / self._processed_attack_count
        )
        logger.info(
            "Average IP processing time for batch: average=%.3f ms processed=%s",
            average_seconds * 1000,
            self._processed_attack_count,
        )
