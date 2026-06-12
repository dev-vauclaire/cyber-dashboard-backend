from __future__ import annotations

from psycopg import Connection

from common_ip_correlator.domain.attack import Attack
from common_ip_correlator._runtime import ensure_backend_root_on_path
from common_ip_correlator.db import PostgresDatabase

ensure_backend_root_on_path()

from packages.database.repositories import CommonIpAttackRepository


class AttackRepository:
    # Responsabilite : lire et mettre a jour les attaques a corriger dans la base.

    def __init__(self, database: PostgresDatabase) -> None:
        # Initialiser le repository des attaques.
        self._repository = CommonIpAttackRepository(database)

    def claim_pending_batch(self, limit: int) -> list[Attack]:
        # Recuperer de maniere atomique un lot d'attaques pending et les passer en processing.
        records = self._repository.claim_pending_batch(limit)
        return [Attack.from_record(record) for record in records]

    def mark_processed(
        self,
        attack_id: int,
        *,
        connection: Connection | None = None,
    ) -> None:
        # Passer une attaque au statut completed.
        self._repository.mark_processed(attack_id, connection=connection)

    def reset_to_pending(self, attack_id: int) -> None:
        # Replacer une attaque au statut pending apres echec de traitement.
        self._repository.reset_to_pending(attack_id)

    def requeue_processing_attacks(self) -> int:
        # Replacer au demarrage les attaques eventuellement bloquees en processing.
        return self._repository.requeue_processing_attacks()
