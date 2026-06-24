"""Routeur principal de l'API."""

from fastapi import APIRouter

from cyber_dashboard_api.api.routes.alerts import router as alerts_router
from cyber_dashboard_api.api.routes.attacks import router as attacks_router
from cyber_dashboard_api.api.routes.attacks_collector_config import (
    router as attacks_collector_config_router,
)
from cyber_dashboard_api.api.routes.cti_config import router as cti_config_router
from cyber_dashboard_api.api.routes.cti_enrichment import (
    router as cti_enrichment_router,
)
from cyber_dashboard_api.api.routes.dashboard import router as dashboard_router
from cyber_dashboard_api.api.routes.health import router as health_router
from cyber_dashboard_api.api.routes.retention_policies import (
    router as retention_policies_router,
)
from cyber_dashboard_api.api.routes.sources import router as sources_router
from cyber_dashboard_api.api.routes.stats import router as stats_router
from cyber_dashboard_api.api.routes.smtp_config import router as smtp_config_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(dashboard_router)
api_router.include_router(sources_router)
api_router.include_router(alerts_router)
api_router.include_router(stats_router)
api_router.include_router(attacks_router)
api_router.include_router(cti_config_router)
api_router.include_router(cti_enrichment_router)
api_router.include_router(smtp_config_router)
api_router.include_router(attacks_collector_config_router)
api_router.include_router(retention_policies_router)
