from __future__ import annotations

from common_ip_correlator.domain.seen_ip_registry import SeenIpRegistry
from common_ip_correlator.repositories.state_repository import StateRepository


class StateLoader:
    # Responsabilite : charger l'etat initial du correlator depuis la base.

    def __init__(self, state_repository: StateRepository) -> None:
        # Initialiser le chargeur d'etat.
        self._state_repository = state_repository

    def load_registry(self) -> SeenIpRegistry:
        # Construire la structure memoire a partir de l'etat persistant.
        return SeenIpRegistry(self._state_repository.load_seen_ips())
