"""Types SQLAlchemy/PostgreSQL derives des enums Python partages."""

from __future__ import annotations

from sqlalchemy import Enum as SqlEnum

from .enums import AttacksCollectorType, CorrelationStatus


status_correlation_enum = SqlEnum(
    CorrelationStatus,
    name="status_correlation",
    native_enum=True,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)


attacks_collector_type_enum = SqlEnum(
    AttacksCollectorType,
    name="attacks_collector_type",
    native_enum=True,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)
