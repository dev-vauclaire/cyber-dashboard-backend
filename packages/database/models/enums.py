"""Enums SQLAlchemy / PostgreSQL utilises par les modeles."""

from __future__ import annotations

from enum import Enum

from sqlalchemy import Enum as SqlEnum


class CorrelationStatus(str, Enum):
    """Statuts de correlation d'une attaque."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


status_correlation_enum = SqlEnum(
    CorrelationStatus,
    name="status_correlation",
    native_enum=True,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)


class AttacksCollectorType(str, Enum):
    """Types de collecteurs d'attaques supportes."""

    OGO = "ogo"
    SERENICITY = "serenicity"


attacks_collector_type_enum = SqlEnum(
    AttacksCollectorType,
    name="attacks_collector_type",
    native_enum=True,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)
