"""Schemas de reponse pour la vue d'ensemble du dashboard."""

from __future__ import annotations

from .common import ApiSchema


class DashboardOverviewSchema(ApiSchema):
    """Resume global des principaux compteurs du dashboard."""

    total_attacks: int
    total_common_ip_alerts: int
    total_active_sources: int
    total_inactive_sources: int
