"""Spécialisation de la rétention pour la table des attaques."""

from __future__ import annotations

from datetime import datetime

from packages.database.repositories import AttackRepository

from cyber_dashboard_scheduler.db import PostgresDatabase


class AttackRetentionService:
    """Supprime les attaques plus anciennes que la date limite calculée."""

    target_table = "attacks"

    def __init__(self, database: PostgresDatabase) -> None:
        self._attack_repository = AttackRepository(database)

    def delete_before(self, *, date_limit: datetime) -> int:
        """Applique la politique de rétention sur `attacks`."""
        return self._attack_repository.delete_attacks_before(occurred_before=date_limit)
