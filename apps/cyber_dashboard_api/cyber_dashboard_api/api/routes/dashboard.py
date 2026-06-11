"""Routes REST pour le dashboard."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from cyber_dashboard_api.api.dependencies import get_dashboard_repository
from cyber_dashboard_api.api.schemas import DashboardOverviewSchema
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
