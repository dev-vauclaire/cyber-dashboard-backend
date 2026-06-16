"""Schemas de reponse pour la vue d'ensemble du dashboard."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import field_validator

from .common import ApiSchema
from .common import strip_ip_prefix


class DashboardOverviewSchema(ApiSchema):
    """Resume global des principaux compteurs du dashboard."""

    total_attacks: int
    total_common_ip_alerts: int
    total_active_sources: int
    total_inactive_sources: int


class DashboardTopologyCollectorSchema(ApiSchema):
    """Noeud collecteur expose pour la cartographie du dashboard."""

    id: int
    name: str
    collector_type: Literal["ogo", "serenicity"]
    is_active: bool
    inventory_requested: bool
    last_validation_status: str | None
    last_validation_at: datetime | None
    last_validation_error: str | None


class DashboardTopologySourceSchema(ApiSchema):
    """Noeud source expose pour la cartographie du dashboard."""

    source_id: int
    source_name: str
    source_color: str | None
    source_is_active: bool
    sensor_type_code: str
    sensor_type_label: str
    collector_id: int | None
    collector_type: Literal["ogo", "serenicity"] | None
    alert_count: int
    domain_name: str | None
    external_id: str | None
    last_inventory_at: datetime | None
    last_inventory_status: str | None
    last_inventory_success_at: datetime | None
    last_inventory_error_at: datetime | None
    last_inventory_error_message: str | None
    last_collection_status: str | None
    last_collection_success_at: datetime | None
    last_collection_error_at: datetime | None
    last_collection_error_message: str | None


class DashboardTopologyAlertSchema(ApiSchema):
    """Noeud alerte expose pour la cartographie du dashboard."""

    alert_id: int
    attacker_ip: str
    distinct_source_count: int
    first_seen_at: datetime
    last_seen_at: datetime

    @field_validator("attacker_ip", mode="before")
    @classmethod
    def strip_attacker_ip_prefix(cls, value: object) -> str:
        """Retire le suffixe CIDR des adresses IP exposees."""
        return strip_ip_prefix(value)


class DashboardTopologyAlertLinkSchema(ApiSchema):
    """Lien source -> alerte expose pour la cartographie du dashboard."""

    alert_id: int
    source_id: int
    first_seen_at: datetime
    last_seen_at: datetime
    hit_count: int


class DashboardTopologyResponseSchema(ApiSchema):
    """Representation de la cartographie collecteurs -> sources -> alertes."""

    collectors: list[DashboardTopologyCollectorSchema]
    sources: list[DashboardTopologySourceSchema]
    alerts: list[DashboardTopologyAlertSchema]
    alert_links: list[DashboardTopologyAlertLinkSchema]
