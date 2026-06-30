"""Routes REST pour les configurations CTI."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Path

from cyber_dashboard_api.api.dependencies import get_cti_config_service
from cyber_dashboard_api.api.schemas import (
    CtiConfigListResponseSchema,
    CtiConfigSchema,
    CtiConfigUpdateRequestSchema,
)
from cyber_dashboard_api.services import CtiConfigService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cti-config", tags=["cti-config"])
CTI_CODE_PATTERN = r"^[a-z0-9_]+$"


@router.get("", response_model=CtiConfigListResponseSchema)
def list_cti_configs(
    cti_config_service: CtiConfigService = Depends(get_cti_config_service),
) -> CtiConfigListResponseSchema:
    """Retourne toutes les configurations CTI publiques."""
    logger.info("endpoint=cti_config_list event=requested")
    return CtiConfigListResponseSchema(items=cti_config_service.list_configs())


@router.get("/{code}", response_model=CtiConfigSchema)
def get_cti_config(
    code: str = Path(..., min_length=1, max_length=50, pattern=CTI_CODE_PATTERN),
    cti_config_service: CtiConfigService = Depends(get_cti_config_service),
) -> CtiConfigSchema:
    """Retourne une configuration CTI publique par code."""
    logger.info("endpoint=cti_config_get event=requested code=%s", code)
    return CtiConfigSchema(**cti_config_service.get_config(code))


@router.patch("/{code}", response_model=CtiConfigSchema)
def update_cti_config(
    payload: CtiConfigUpdateRequestSchema,
    code: str = Path(..., min_length=1, max_length=50, pattern=CTI_CODE_PATTERN),
    cti_config_service: CtiConfigService = Depends(get_cti_config_service),
) -> CtiConfigSchema:
    """Met a jour une configuration CTI."""
    logger.info("endpoint=cti_config_update event=requested code=%s", code)
    return CtiConfigSchema(
        **cti_config_service.update_config(code=code, payload=payload)
    )


@router.post("/{code}/activate", response_model=CtiConfigSchema)
def activate_cti_config(
    code: str = Path(..., min_length=1, max_length=50, pattern=CTI_CODE_PATTERN),
    cti_config_service: CtiConfigService = Depends(get_cti_config_service),
) -> CtiConfigSchema:
    """Active une configuration CTI."""
    logger.info("endpoint=cti_config_activate event=requested code=%s", code)
    return CtiConfigSchema(**cti_config_service.activate_config(code))


@router.post("/{code}/deactivate", response_model=CtiConfigSchema)
def deactivate_cti_config(
    code: str = Path(..., min_length=1, max_length=50, pattern=CTI_CODE_PATTERN),
    cti_config_service: CtiConfigService = Depends(get_cti_config_service),
) -> CtiConfigSchema:
    """Desactive une configuration CTI."""
    logger.info("endpoint=cti_config_deactivate event=requested code=%s", code)
    return CtiConfigSchema(**cti_config_service.deactivate_config(code))


@router.delete("/{code}/api-key", response_model=CtiConfigSchema)
def delete_cti_api_key(
    code: str = Path(..., min_length=1, max_length=50, pattern=CTI_CODE_PATTERN),
    cti_config_service: CtiConfigService = Depends(get_cti_config_service),
) -> CtiConfigSchema:
    """Supprime la cle API d'une configuration CTI."""
    logger.info("endpoint=cti_config_delete_api_key event=requested code=%s", code)
    return CtiConfigSchema(**cti_config_service.delete_api_key(code))
