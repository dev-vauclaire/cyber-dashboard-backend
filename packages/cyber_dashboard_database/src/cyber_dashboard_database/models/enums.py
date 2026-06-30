"""Enums Python partages par les modeles et repositories."""

from __future__ import annotations

from enum import Enum


class CorrelationStatus(str, Enum):
    """Statuts de correlation d'une attaque."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class AttacksCollectorType(str, Enum):
    """Types de collecteurs d'attaques supportes."""

    OGO = "ogo"
    SERENICITY = "serenicity"
