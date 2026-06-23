"""Facade locale vers les repositories partages du monorepo."""

from __future__ import annotations

from packages.database.repositories import (
    AlertRepository,
    AttackRepository,
    AttacksCollectorConfigRepository,
    CtiConfigRepository,
    DashboardRepository,
    RetentionPolicyRepository,
    SensorTypeRepository,
    SmtpConfigRepository,
    SourceRepository,
    StatisticsRepository,
)

__all__ = [
    "AlertRepository",
    "AttackRepository",
    "AttacksCollectorConfigRepository",
    "CtiConfigRepository",
    "DashboardRepository",
    "RetentionPolicyRepository",
    "SensorTypeRepository",
    "SmtpConfigRepository",
    "SourceRepository",
    "StatisticsRepository",
]
