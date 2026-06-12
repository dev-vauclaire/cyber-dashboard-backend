from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from common_ip_correlator.domain.ip_address import IpAddress


@dataclass(slots=True)
class CommonIpAlert:
    # Responsabilite : representer les donnees minimales d'une alerte d'IP commune.

    attacker_ip: IpAddress
    first_seen_at: datetime
    last_seen_at: datetime
    distinct_source_count: int
    status: str = "open"
    id: int | None = None

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "CommonIpAlert":
        # Construire une alerte a partir d'une ligne de base.
        return cls(
            id=int(record["id"]),
            attacker_ip=IpAddress(str(record["attacker_ip"])),
            first_seen_at=record["first_seen_at"],
            last_seen_at=record["last_seen_at"],
            distinct_source_count=int(record["distinct_source_count"]),
            status=str(record["status"]),
        )

    def refresh(
        self,
        *,
        first_seen_at: datetime,
        last_seen_at: datetime,
        distinct_source_count: int,
    ) -> None:
        # Mettre a jour les champs temporels et le nombre de sources distinctes.
        self.first_seen_at = first_seen_at
        self.last_seen_at = last_seen_at
        self.distinct_source_count = distinct_source_count
