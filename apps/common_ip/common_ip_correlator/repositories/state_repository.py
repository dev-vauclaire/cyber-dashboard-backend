from __future__ import annotations

from common_ip_correlator.domain.common_ip_alert_source import CommonIpAlertSource
from common_ip_correlator._runtime import ensure_backend_root_on_path
from common_ip_correlator.db import PostgresDatabase

ensure_backend_root_on_path()

from packages.database.repositories import CommonIpStateRepository


class StateRepository:
    # Responsabilite : reconstruire l'etat memoire du correlator a partir de la base.

    def __init__(self, database: PostgresDatabase) -> None:
        # Initialiser le repository charge de l'etat persistant.
        self._repository = CommonIpStateRepository(database)

    def load_seen_ips(self) -> dict[str, list[CommonIpAlertSource]]:
        # Recuperer la liste des IP deja traitees et leurs resumes par source.
        seen_ips: dict[str, list[CommonIpAlertSource]] = {}
        records = self._repository.load_seen_ips()

        for record in records:
            attacker_ip = str(record["attacker_ip"])
            seen_ips.setdefault(attacker_ip, []).append(CommonIpAlertSource.from_record(record))
        return seen_ips
