"""Routes REST pour la consultation des attaques."""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from cyber_dashboard_api.api.dependencies import get_attack_repository
from cyber_dashboard_api.api.schemas import AttackItemSchema, AttackListResponseSchema
from cyber_dashboard_api.api.schemas.common import PaginationSchema
from cyber_dashboard_api.api.validation import (
    normalize_optional_filter,
    validate_datetime_range,
)
from cyber_dashboard_api.models import Pagination
from cyber_dashboard_api.repositories import AttackRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/attacks", tags=["attacks"])


@router.get("", response_model=AttackListResponseSchema)
def list_attacks(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sensor_type: str | None = Query(default=None, max_length=50),
    source_id: int | None = Query(default=None, ge=1),
    from_at: datetime | None = Query(default=None, alias="from"),
    to_at: datetime | None = Query(default=None, alias="to"),
    attack_type: str | None = Query(default=None, max_length=100),
    attack_repository: AttackRepository = Depends(get_attack_repository),
) -> AttackListResponseSchema:
    """Retourne la liste paginee des attaques avec filtres optionnels."""
    validate_datetime_range(from_at, to_at)
    normalized_sensor_type = normalize_optional_filter(
        name="sensor_type",
        value=sensor_type,
        max_length=50,
    )
    normalized_attack_type = normalize_optional_filter(
        name="attack_type",
        value=attack_type,
        max_length=100,
    )
    logger.info(
        "endpoint=attacks_list event=requested page=%s page_size=%s sensor_type=%s source_id=%s from=%s to=%s attack_type=%s",
        page,
        page_size,
        normalized_sensor_type,
        source_id,
        from_at,
        to_at,
        normalized_attack_type,
    )

    total_items = attack_repository.count_attacks(
        source_id=source_id,
        sensor_type_code=normalized_sensor_type,
        attack_type=normalized_attack_type,
        occurred_from=from_at,
        occurred_to=to_at,
    )
    pagination = Pagination(page=page, page_size=page_size, total_items=total_items)
    rows = attack_repository.list_attacks(
        limit=page_size,
        offset=pagination.offset,
        source_id=source_id,
        sensor_type_code=normalized_sensor_type,
        attack_type=normalized_attack_type,
        occurred_from=from_at,
        occurred_to=to_at,
    )

    items = [AttackItemSchema(**row) for row in rows]
    return AttackListResponseSchema(
        pagination=PaginationSchema(
            page=pagination.page,
            page_size=pagination.page_size,
            total_items=pagination.total_items,
            total_pages=pagination.total_pages,
        ),
        items=items,
    )
