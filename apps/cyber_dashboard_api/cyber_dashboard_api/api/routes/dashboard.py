"""Routes REST pour le dashboard."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from cyber_dashboard_api.api.dependencies import get_dashboard_repository
from cyber_dashboard_api.api.schemas import (
    DashboardOverviewSchema,
    DashboardTopologyResponseSchema,
)
from cyber_dashboard_api.repositories import DashboardRepository


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=DashboardOverviewSchema)
def get_dashboard_overview(
    dashboard_repository: DashboardRepository = Depends(get_dashboard_repository),
) -> DashboardOverviewSchema:
    """Retourne les compteurs principaux du dashboard."""
    logger.info("endpoint=dashboard_overview event=requested")
    overview = dashboard_repository.get_overview_counts()
    return DashboardOverviewSchema(**overview)


@router.get("/topology", response_model=DashboardTopologyResponseSchema)
def get_dashboard_topology(
    min_distinct_source_count: Annotated[int, Query(ge=1)] = 3,
    alert_limit: Annotated[int | None, Query(ge=1, le=500)] = None,
    dashboard_repository: DashboardRepository = Depends(get_dashboard_repository),
) -> DashboardTopologyResponseSchema:
    """Retourne la cartographie collecteurs -> sources -> alertes du dashboard."""
    logger.info(
        "endpoint=dashboard_topology event=requested min_distinct_source_count=%s alert_limit=%s",
        min_distinct_source_count,
        alert_limit,
    )
    topology = dashboard_repository.get_topology(
        min_distinct_source_count=min_distinct_source_count,
        alert_limit=alert_limit,
    )
    return DashboardTopologyResponseSchema(**topology)
