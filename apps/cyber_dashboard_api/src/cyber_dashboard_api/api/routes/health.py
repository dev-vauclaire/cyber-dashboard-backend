"""Route technique minimale pour verifier que l'application demarre."""

from __future__ import annotations

import logging

from fastapi import APIRouter

from cyber_dashboard_api.api.schemas import HealthcheckSchema

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthcheckSchema)
def healthcheck() -> HealthcheckSchema:
    """Retourne un statut simple de disponibilite."""
    logger.info("endpoint=health event=requested")
    return HealthcheckSchema(status="ok")
