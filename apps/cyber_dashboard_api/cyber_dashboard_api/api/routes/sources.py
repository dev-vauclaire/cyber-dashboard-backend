"""Routes REST pour les sources et l'inventaire des capteurs."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Path

from cyber_dashboard_api.api.dependencies import get_source_service
from cyber_dashboard_api.api.schemas import (
    SensorInventoryItemSchema,
    SensorInventoryResponseSchema,
    SourceItemSchema,
    SourceListResponseSchema,
    SourceRenameRequestSchema,
    SourceStatusUpdateRequestSchema,
    SourceColorUpdateRequestSchema,
)
from cyber_dashboard_api.services import SourceService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sources", tags=["sources"])


@router.get("/inventory", response_model=SensorInventoryResponseSchema)
def get_sources_inventory(
    source_service: SourceService = Depends(get_source_service),
) -> SensorInventoryResponseSchema:
    """Retourne l'inventaire agrege des sources par type de capteur."""
    logger.info("endpoint=sources_inventory event=requested")
    items = [
        SensorInventoryItemSchema(**item)
        for item in source_service.get_sensor_inventory()
    ]
    return SensorInventoryResponseSchema(items=items)


@router.get("", response_model=SourceListResponseSchema)
def list_sources(
    source_service: SourceService = Depends(get_source_service),
) -> SourceListResponseSchema:
    """Retourne la liste simple des sources individuelles."""
    logger.info("endpoint=sources_list event=requested")
    items = [SourceItemSchema(**item) for item in source_service.list_sources()]
    return SourceListResponseSchema(items=items)


@router.patch("/{source_id}/name", response_model=SourceItemSchema)
def rename_source(
    payload: SourceRenameRequestSchema,
    source_id: int = Path(..., ge=1),
    source_service: SourceService = Depends(get_source_service),
) -> SourceItemSchema:
    """Met a jour le nom d'une source a partir de son identifiant."""
    logger.info("endpoint=source_rename event=requested source_id=%s", source_id)
    item = source_service.rename_source(
        source_id=source_id,
        source_name=payload.source_name,
    )
    return SourceItemSchema(**item)


@router.patch("/{source_id}/is_active", response_model=SourceItemSchema)
def update_source_status(
    payload: SourceStatusUpdateRequestSchema,
    source_id: int = Path(..., ge=1),
    source_service: SourceService = Depends(get_source_service),
) -> SourceItemSchema:
    """Met a jour le statut d'une source a partir de son identifiant."""
    logger.info("endpoint=source_update_status event=requested source_id=%s", source_id)
    item = source_service.update_source_status(
        source_id=source_id,
        is_active=payload.is_active,
    )
    return SourceItemSchema(**item)


@router.patch("/{source_id}/color", response_model=SourceItemSchema)
def update_source_color(
    payload: SourceColorUpdateRequestSchema,
    source_id: int = Path(..., ge=1),
    source_service: SourceService = Depends(get_source_service),
) -> SourceItemSchema:
    """Met a jour la couleur d'une source a partir de son identifiant."""
    logger.info("endpoint=source_update_color event=requested source_id=%s", source_id)
    item = source_service.update_source_color(
        source_id=source_id,
        color=payload.color,
    )
    return SourceItemSchema(**item)
