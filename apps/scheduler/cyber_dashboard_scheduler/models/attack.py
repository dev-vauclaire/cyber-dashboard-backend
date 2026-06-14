"""Modèles internes liés à la collecte d'attaques."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class Attack:
    """Représente une attaque normalisée prête à être persistée."""

    source_id: int
    source_event_id: str | None
    attacker_ip: str
    occurred_at: datetime
    collected_at: datetime
    attack_type: str | None
    raw_payload: dict[str, Any] | None
