"""Routes REST pour les politiques de retention."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Path

from cyber_dashboard_api.api.dependencies import get_retention_policy_service
from cyber_dashboard_api.api.schemas import (
    RetentionPolicyListResponseSchema,
    RetentionPolicySchema,
    RetentionPolicyUpdateRequestSchema,
)
from cyber_dashboard_api.services import RetentionPolicyService


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/retention-policies", tags=["retention-policies"])


@router.get("", response_model=RetentionPolicyListResponseSchema)
def list_retention_policies(
    retention_policy_service: RetentionPolicyService = Depends(
        get_retention_policy_service
    ),
) -> RetentionPolicyListResponseSchema:
    """Retourne toutes les politiques de retention."""
    logger.info("endpoint=retention_policies_list event=requested")
    return RetentionPolicyListResponseSchema(
        items=retention_policy_service.list_policies()
    )


@router.get("/{target_table}", response_model=RetentionPolicySchema)
def get_retention_policy(
    target_table: str = Path(..., min_length=1, max_length=100),
    retention_policy_service: RetentionPolicyService = Depends(
        get_retention_policy_service
    ),
) -> RetentionPolicySchema:
    """Retourne une politique de retention."""
    logger.info(
        "endpoint=retention_policy_get event=requested target_table=%s",
        target_table,
    )
    return RetentionPolicySchema(**retention_policy_service.get_policy(target_table))


@router.patch("/{target_table}", response_model=RetentionPolicySchema)
def update_retention_policy(
    payload: RetentionPolicyUpdateRequestSchema,
    target_table: str = Path(..., min_length=1, max_length=100),
    retention_policy_service: RetentionPolicyService = Depends(
        get_retention_policy_service
    ),
) -> RetentionPolicySchema:
    """Met a jour une politique de retention."""
    logger.info(
        "endpoint=retention_policy_update event=requested target_table=%s",
        target_table,
    )
    return RetentionPolicySchema(
        **retention_policy_service.update_policy(
            target_table=target_table,
            payload=payload,
        )
    )
