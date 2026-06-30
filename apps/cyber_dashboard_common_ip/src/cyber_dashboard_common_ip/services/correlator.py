from __future__ import annotations

import logging
import time
from typing import Callable

from psycopg import Connection

from cyber_dashboard_common_ip.config import CorrelatorConfig
from cyber_dashboard_common_ip.db import PostgresDatabase
from cyber_dashboard_common_ip.domain.attack import Attack
from cyber_dashboard_common_ip.domain.common_ip_alert import CommonIpAlert
from cyber_dashboard_common_ip.domain.common_ip_alert_source import CommonIpAlertSource
from cyber_dashboard_common_ip.domain.ip_address import IpAddress
from cyber_dashboard_common_ip.domain.seen_ip_registry import SeenIpRegistry
from cyber_dashboard_common_ip.repositories.alert_repository import AlertRepository
from cyber_dashboard_common_ip.repositories.attack_repository import AttackRepository
from cyber_dashboard_common_ip.services.batch_processing_time_tracker import (
    BatchProcessingTimeTracker,
)
from cyber_dashboard_common_ip.services.state_loader import StateLoader


class Correlator:
    # Responsabilite : executer la boucle de correlation et appliquer les regles metier.

    def __init__(
        self,
        config: CorrelatorConfig,
        database: PostgresDatabase,
        attack_repository: AttackRepository,
        alert_repository: AlertRepository,
        state_loader: StateLoader,
        *,
        sleep_fn: Callable[[float], None] = time.sleep,
        perf_counter_fn: Callable[[], float] = time.perf_counter,
        logger: logging.Logger | None = None,
    ) -> None:
        # Initialiser le service principal de correlation.
        self._config = config
        self._database = database
        self._attack_repository = attack_repository
        self._alert_repository = alert_repository
        self._state_loader = state_loader
        self._sleep_fn = sleep_fn
        self._perf_counter_fn = perf_counter_fn
        self._logger = logger or logging.getLogger(self.__class__.__name__)
        self._registry = SeenIpRegistry()

    def run(self) -> None:
        # Lancer la boucle principale du correlator.
        self._logger.info("Starting common IP correlator")
        recovered_attacks = self._attack_repository.requeue_processing_attacks()
        if recovered_attacks:
            self._logger.info(
                "Requeued %s attacks left in processing", recovered_attacks
            )

        self._registry = self._state_loader.load_registry()
        self._logger.info(
            "Loaded %s known IPs in memory",
            len(self._registry.snapshot()),
        )

        while True:
            self.process_next_batch()

    def process_next_batch(self) -> int:
        # Recuperer un lot pending, le traiter puis le finaliser.
        attacks = self._attack_repository.claim_pending_batch(self._config.batch_size)
        if not attacks:
            self._logger.info(
                "No pending attacks found, waiting %s seconds",
                self._config.poll_interval_seconds,
            )
            self.wait_next_cycle()
            return 0

        self._logger.info("Claimed %s attacks for processing", len(attacks))
        batch_processing_time_tracker = BatchProcessingTimeTracker(
            enabled=self._config.compute_average_processing_time,
            perf_counter_fn=self._perf_counter_fn,
        )
        for attack in attacks:
            start_time = batch_processing_time_tracker.start_attack()
            try:
                self.process_attack(attack)
                batch_processing_time_tracker.record_completed_attack(start_time)
                self._logger.info(
                    "Processed attack id=%s ip=%s", attack.id, attack.attacker_ip
                )
            except Exception:
                self._logger.exception("Failed to process attack id=%s", attack.id)
                self._attack_repository.reset_to_pending(attack.id)

        batch_processing_time_tracker.log_batch_average(self._logger)
        return len(attacks)

    def process_attack(self, attack: Attack) -> None:
        # Appliquer les regles de correlation sur une attaque.
        if not attack.attacker_ip.is_valid():
            raise ValueError(f"Invalid attacker IP: {attack.attacker_ip.value}")

        normalized_ip = attack.attacker_ip.normalize()
        projected_source_summaries = self._registry.preview_source_summaries(
            normalized_ip,
            source_id=attack.source_id,
            occurred_at=attack.occurred_at,
        )

        with self._database.transaction() as connection:
            if len(projected_source_summaries) > 1:
                self.update_alerts(
                    attack,
                    source_summaries=projected_source_summaries,
                    connection=connection,
                )
            self._attack_repository.mark_processed(attack.id, connection=connection)

        self._registry.register_source(
            normalized_ip, attack.source_id, attack.occurred_at
        )

    def update_alerts(
        self,
        attack: Attack,
        *,
        source_summaries: list[CommonIpAlertSource],
        connection: Connection,
    ) -> None:
        # Creer ou mettre a jour les alertes liees a une IP commune.
        normalized_ip = attack.attacker_ip.normalize()
        if len(source_summaries) < 2:
            return

        existing_alert = self._alert_repository.find_by_ip(
            normalized_ip,
            connection=connection,
        )
        first_seen_at = min(summary.first_seen_at for summary in source_summaries)
        last_seen_at = max(summary.last_seen_at for summary in source_summaries)

        alert = CommonIpAlert(
            attacker_ip=IpAddress(normalized_ip),
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            distinct_source_count=len(source_summaries),
            status="open",
            id=existing_alert.id if existing_alert is not None else None,
        )
        persisted_alert = self._alert_repository.upsert_alert(
            alert,
            connection=connection,
        )

        for summary in source_summaries:
            summary.alert_id = persisted_alert.id
            self._alert_repository.upsert_alert_source(
                summary,
                connection=connection,
            )

        action = "updated" if existing_alert is not None else "created"
        self._logger.info(
            "%s alert for ip=%s with %s sources",
            action.capitalize(),
            normalized_ip,
            len(source_summaries),
        )

    def wait_next_cycle(self) -> None:
        # Attendre avant de relancer une nouvelle iteration de traitement.
        self._sleep_fn(self._config.poll_interval_seconds)
