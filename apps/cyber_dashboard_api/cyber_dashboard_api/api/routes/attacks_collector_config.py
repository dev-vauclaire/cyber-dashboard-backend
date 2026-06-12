"""Routes REST pour les configurations de collecteurs d'attaques."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Path, Response, status

from cyber_dashboard_api.api.dependencies import get_attacks_collector_config_service
from cyber_dashboard_api.api.schemas import (
    AttacksCollectorConfigCreateRequestSchema,
    AttacksCollectorConfigListResponseSchema,
    AttacksCollectorConfigSchema,
    AttacksCollectorInventoryRequestResponseSchema,
    AttacksCollectorConfigUpdateRequestSchema,
)
from cyber_dashboard_api.services import AttacksCollectorConfigService


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/attacks-collector-config",
    tags=["attacks-collector-config"],
)


@router.get("", response_model=AttacksCollectorConfigListResponseSchema)
def list_attacks_collector_configs(
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigListResponseSchema:
    """Retourne toutes les configurations publiques de collecteurs."""
    logger.info("endpoint=attacks_collector_config_list event=requested")
    return AttacksCollectorConfigListResponseSchema(
        items=attacks_collector_config_service.list_configs()
    )


@router.get("/{config_id}", response_model=AttacksCollectorConfigSchema)
def get_attacks_collector_config(
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigSchema:
    """Retourne une configuration particulière d'un collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_get event=requested config_id=%s",
        config_id,
    )
    return AttacksCollectorConfigSchema(
        **attacks_collector_config_service.get_config(config_id)
    )


@router.post("", response_model=AttacksCollectorConfigSchema, status_code=status.HTTP_201_CREATED)
def create_attacks_collector_config(
    payload: AttacksCollectorConfigCreateRequestSchema,
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigSchema:
    """Cree une configuration de collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_create event=requested collector_type=%s",
        payload.collector_type,
    )
    return AttacksCollectorConfigSchema(
        **attacks_collector_config_service.create_config(payload)
    )


@router.patch("/{config_id}", response_model=AttacksCollectorConfigSchema)
def update_attacks_collector_config(
    payload: AttacksCollectorConfigUpdateRequestSchema,
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigSchema:
    """Met a jour une configuration de collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_update event=requested config_id=%s",
        config_id,
    )
    return AttacksCollectorConfigSchema(
        **attacks_collector_config_service.update_config(
            config_id=config_id,
            payload=payload,
        )
    )


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_attacks_collector_config(
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> Response:
    """Supprime une configuration de collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_delete event=requested config_id=%s",
        config_id,
    )
    attacks_collector_config_service.delete_config(config_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{config_id}/activate", response_model=AttacksCollectorConfigSchema)
def activate_attacks_collector_config(
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigSchema:
    """Active une configuration de collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_activate event=requested config_id=%s",
        config_id,
    )
    return AttacksCollectorConfigSchema(
        **attacks_collector_config_service.activate_config(config_id)
    )


@router.post("/{config_id}/deactivate", response_model=AttacksCollectorConfigSchema)
def deactivate_attacks_collector_config(
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigSchema:
    """Desactive une configuration de collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_deactivate event=requested config_id=%s",
        config_id,
    )
    return AttacksCollectorConfigSchema(
        **attacks_collector_config_service.deactivate_config(config_id)
    )


@router.delete("/{config_id}/api-key", response_model=AttacksCollectorConfigSchema)
def delete_attacks_collector_api_key(
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigSchema:
    """Supprime la cle API chiffree d'une configuration de collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_delete_api_key event=requested config_id=%s",
        config_id,
    )
    return AttacksCollectorConfigSchema(
        **attacks_collector_config_service.delete_api_key(config_id)
    )


@router.delete("/{config_id}/email", response_model=AttacksCollectorConfigSchema)
def delete_attacks_collector_email(
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorConfigSchema:
    """Supprime l'email chiffre d'une configuration de collecteur."""
    logger.info(
        "endpoint=attacks_collector_config_delete_email event=requested config_id=%s",
        config_id,
    )
    return AttacksCollectorConfigSchema(
        **attacks_collector_config_service.delete_email(config_id)
    )


@router.post(
    "/{config_id}/request-inventory",
    response_model=AttacksCollectorInventoryRequestResponseSchema,
)
def request_attacks_collector_inventory(
    config_id: int = Path(..., ge=1),
    attacks_collector_config_service: AttacksCollectorConfigService = Depends(
        get_attacks_collector_config_service
    ),
) -> AttacksCollectorInventoryRequestResponseSchema:
    """Demande un inventaire futur sans lancer le scheduler directement."""
    logger.info(
        "endpoint=attacks_collector_request_inventory event=requested config_id=%s",
        config_id,
    )
    return AttacksCollectorInventoryRequestResponseSchema(
        **attacks_collector_config_service.request_inventory(config_id=config_id)
    )
