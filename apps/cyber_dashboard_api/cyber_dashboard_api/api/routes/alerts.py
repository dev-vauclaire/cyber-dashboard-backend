"""Routes REST pour les alertes IP communes."""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Path, Query

from cyber_dashboard_api.api.errors import BadRequestError, NotFoundError
from cyber_dashboard_api.api.dependencies import (
    get_alert_email_service,
    get_alert_repository,
)
from cyber_dashboard_api.api.schemas import (
    AlertDetailItemSchema,
    AlertDetailResponseSchema,
    AlertEmailRequestSchema,
    AlertEmailResponseSchema,
    AlertListItemSchema,
    AlertListResponseSchema,
)
from cyber_dashboard_api.api.schemas.common import PaginationSchema
from cyber_dashboard_api.api.validation import validate_datetime_range
from cyber_dashboard_api.models import Pagination
from cyber_dashboard_api.repositories import AlertRepository
from cyber_dashboard_api.services import AlertEmailService


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts/common-ips", tags=["alerts"])


def validate_source_ids(source_ids: list[int] | None) -> list[int] | None:
    """Valide les ids de sources repetes dans la query string."""
    if source_ids is None:
        return None

    if any(source_id < 1 for source_id in source_ids):
        raise BadRequestError(
            code="invalid_source_id",
            message="Le paramètre de requête 'source_id' doit contenir des entiers positifs",
        )

    return source_ids


@router.get("", response_model=AlertListResponseSchema)
def list_common_ip_alerts(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    source_id: list[int] | None = Query(default=None),
    from_at: datetime | None = Query(default=None, alias="from"),
    to_at: datetime | None = Query(default=None, alias="to"),
    min_distinct_source_count: int | None = Query(default=None, ge=1),
    alert_repository: AlertRepository = Depends(get_alert_repository),
) -> AlertListResponseSchema:
    """Retourne la liste paginee des alertes IP communes."""
    validate_datetime_range(from_at, to_at)
    source_ids = validate_source_ids(source_id)
    logger.info(
        "endpoint=alerts_common_ips_list event=requested page=%s limit=%s source_id=%s from=%s to=%s min_distinct_source_count=%s",
        page,
        limit,
        source_ids,
        from_at,
        to_at,
        min_distinct_source_count,
    )

    total_items = alert_repository.count_common_ip_alerts(
        source_ids=source_ids,
        last_seen_from=from_at,
        last_seen_to=to_at,
        min_distinct_source_count=min_distinct_source_count,
    )
    pagination = Pagination(page=page, page_size=limit, total_items=total_items)
    rows = alert_repository.list_common_ip_alerts(
        limit=limit,
        offset=pagination.offset,
        source_ids=source_ids,
        last_seen_from=from_at,
        last_seen_to=to_at,
        min_distinct_source_count=min_distinct_source_count,
    )

    items = [AlertListItemSchema(**row) for row in rows]
    return AlertListResponseSchema(
        pagination=PaginationSchema(
            page=pagination.page,
            page_size=pagination.page_size,
            total_items=pagination.total_items,
            total_pages=pagination.total_pages,
        ),
        items=items,
    )


@router.get("/{alert_id}", response_model=AlertDetailResponseSchema)
def get_common_ip_alert_detail(
    alert_id: int = Path(..., ge=1),
    alert_repository: AlertRepository = Depends(get_alert_repository),
) -> AlertDetailResponseSchema:
    """Retourne le detail d'une alerte IP commune."""
    logger.info(
        "endpoint=alerts_common_ips_detail event=requested alert_id=%s",
        alert_id,
    )
    rows = alert_repository.get_alert_detail_by_alert_id(alert_id)
    if not rows:
        raise NotFoundError(
            code="common_ip_alert_not_found",
            message="Alerte IP commune introuvable",
        )

    sources = [
        AlertDetailItemSchema(
            source_id=row["source_id"],
            source_name=row["source_name"],
            sensor_type_code=row.get("sensor_type_code"),
            collector_type=row.get("collector_type"),
            domain_name=row.get("domain_name"),
            external_id=row.get("external_id"),
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            hit_count=row["hit_count"],
        )
        for row in rows
    ]

    return AlertDetailResponseSchema(
        attacker_ip=rows[0]["attacker_ip"],
        sources=sources,
    )


@router.post("/{alert_id}/email", response_model=AlertEmailResponseSchema)
def send_common_ip_alert_email(
    payload: AlertEmailRequestSchema,
    alert_id: int = Path(..., ge=1),
    alert_email_service: AlertEmailService = Depends(get_alert_email_service),
) -> AlertEmailResponseSchema:
    """Envoie manuellement un email d'alerte pour une IP commune."""
    logger.info(
        "endpoint=alerts_common_ips_email event=requested alert_id=%s",
        alert_id,
    )
    return AlertEmailResponseSchema(
        **alert_email_service.send_alert_email(alert_id=alert_id, payload=payload)
    )
