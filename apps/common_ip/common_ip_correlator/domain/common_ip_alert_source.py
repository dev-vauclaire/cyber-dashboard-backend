from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class CommonIpAlertSource:
    # Responsabilite : representer les donnees minimales liees a une alerte pour une source.

    source_id: int
    first_seen_at: datetime
    last_seen_at: datetime
    hit_count: int
    alert_id: int | None = None

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "CommonIpAlertSource":
        # Construire l'association a partir d'un enregistrement de base.
        alert_id = record.get("alert_id")
        return cls(
            alert_id=int(alert_id) if alert_id is not None else None,
            source_id=int(record["source_id"]),
            first_seen_at=record["first_seen_at"],
            last_seen_at=record["last_seen_at"],
            hit_count=int(record["hit_count"]),
        )

    def increment_hit_count(self) -> None:
        # Mettre a jour le nombre d'occurrences pour cette source.
        self.hit_count += 1

    def refresh_dates(self, *, first_seen_at: datetime, last_seen_at: datetime) -> None:
        # Mettre a jour les dates de premiere et derniere observation.
        self.first_seen_at = first_seen_at
        self.last_seen_at = last_seen_at
