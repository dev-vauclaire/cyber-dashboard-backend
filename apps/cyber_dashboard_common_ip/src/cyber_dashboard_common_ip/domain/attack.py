from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from cyber_dashboard_common_ip.domain.ip_address import IpAddress


class AttackStatus(str, Enum):
    # Responsabilite : representer les differents etats persistants d'une attaque.

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class Attack:
    # Responsabilite : representer les donnees minimales d'une attaque utiles au correlator.

    id: int
    source_id: int
    attacker_ip: IpAddress
    occurred_at: datetime
    status: AttackStatus

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Attack":
        # Construire une attaque a partir d'un enregistrement de base.
        raw_status = record.get(
            "status", record.get("correlation_status", AttackStatus.PENDING.value)
        )
        status = (
            raw_status
            if isinstance(raw_status, AttackStatus)
            else AttackStatus(raw_status)
        )
        return cls(
            id=int(record["id"]),
            source_id=int(record["source_id"]),
            attacker_ip=IpAddress(str(record["attacker_ip"])),
            occurred_at=record["occurred_at"],
            status=status,
        )

    def mark_processing(self) -> None:
        # Representer le passage de l'attaque a l'etat processing.
        self.status = AttackStatus.PROCESSING

    def mark_completed(self) -> None:
        # Representer le passage de l'attaque a l'etat completed.
        self.status = AttackStatus.COMPLETED

    def mark_processed(self) -> None:
        # Conserver un alias de compatibilite pour l'ancien nom de methode.
        self.mark_completed()
