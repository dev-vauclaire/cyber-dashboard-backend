"""Facade locale vers les repositories partages du monorepo."""

from __future__ import annotations

from cyber_dashboard_api._runtime import ensure_backend_root_on_path

ensure_backend_root_on_path()

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
