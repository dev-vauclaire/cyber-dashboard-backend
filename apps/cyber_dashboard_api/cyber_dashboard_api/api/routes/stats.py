"""Routes REST pour les statistiques d'attaques."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query

from cyber_dashboard_api.api.dependencies import get_statistics_repository
from cyber_dashboard_api.api.schemas import (
    AttackSourcePercentageSchema,
    AttackStatisticsResponseSchema,
    AttackSourceTimeseriesResponseSchema,
    AttackSourceTimeseriesSeriesSchema,
    AttackSummaryResponseSchema,
    AttackTypePercentageSchema,
    TopAttackTypesResponseSchema,
)
from cyber_dashboard_api.api.validation import validate_datetime_range
from cyber_dashboard_api.repositories import StatisticsRepository


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/stats/attacks", tags=["stats"])
PARIS_TIMEZONE = ZoneInfo("Europe/Paris")


def _build_daily_bucket_starts(
    from_at: datetime,
    to_at: datetime,
) -> list[datetime]:
    """Construit les debuts de jour Paris, exposes sous forme d'instants UTC."""
    current_day = from_at.astimezone(PARIS_TIMEZONE).date()
    last_day = to_at.astimezone(PARIS_TIMEZONE).date()

    bucket_starts_utc: list[datetime] = []
    while current_day <= last_day:
        bucket_start_paris = datetime.combine(
            current_day,
            time.min,
            tzinfo=PARIS_TIMEZONE,
        )
        bucket_starts_utc.append(bucket_start_paris.astimezone(UTC))
        current_day += timedelta(days=1)

    return bucket_starts_utc


@router.get("/summary", response_model=AttackSummaryResponseSchema)
def get_attack_summary(
    from_at: datetime = Query(..., alias="from"),
    to_at: datetime = Query(..., alias="to"),
    statistics_repository: StatisticsRepository = Depends(get_statistics_repository),
) -> AttackSummaryResponseSchema:
    """Retourne le total d'attaques entre deux dates."""
    validate_datetime_range(from_at, to_at)
    logger.info(
        "endpoint=attacks_summary event=requested from=%s to=%s",
        from_at,
        to_at,
    )
    total_attacks = statistics_repository.get_attack_total_between(
        occurred_from=from_at,
        occurred_to=to_at,
    )
    return AttackSummaryResponseSchema(
        from_at=from_at,
        to_at=to_at,
        total_attacks=total_attacks,
    )


@router.get("/by-source", response_model=AttackStatisticsResponseSchema)
def get_attack_distribution_by_source(
    from_at: datetime = Query(..., alias="from"),
    to_at: datetime = Query(..., alias="to"),
    statistics_repository: StatisticsRepository = Depends(get_statistics_repository),
) -> AttackStatisticsResponseSchema:
    """Retourne la repartition des attaques par source entre deux dates."""
    validate_datetime_range(from_at, to_at)
    logger.info(
        "endpoint=attacks_by_source event=requested from=%s to=%s",
        from_at,
        to_at,
    )
    total_attacks = statistics_repository.get_attack_total_between(
        occurred_from=from_at,
        occurred_to=to_at,
    )
    rows = statistics_repository.get_attack_distribution_by_source(
        occurred_from=from_at,
        occurred_to=to_at,
    )
    by_source = [AttackSourcePercentageSchema(**row) for row in rows]
    return AttackStatisticsResponseSchema(
        from_at=from_at,
        to_at=to_at,
        total_attacks=total_attacks,
        by_source=by_source,
    )


@router.get("/by-source-timeseries", response_model=AttackSourceTimeseriesResponseSchema)
def get_attack_timeseries_by_source(
    from_at: datetime = Query(..., alias="from"),
    to_at: datetime = Query(..., alias="to"),
    statistics_repository: StatisticsRepository = Depends(get_statistics_repository),
) -> AttackSourceTimeseriesResponseSchema:
    """Retourne une serie journaliere des attaques par source."""
    validate_datetime_range(from_at, to_at)
    logger.info(
        "endpoint=attacks_by_source_timeseries event=requested from=%s to=%s",
        from_at,
        to_at,
    )

    total_attacks = statistics_repository.get_attack_total_between(
        occurred_from=from_at,
        occurred_to=to_at,
    )
    rows = statistics_repository.get_attack_timeseries_by_source(
        occurred_from=from_at,
        occurred_to=to_at,
    )

    bucket_starts_utc = _build_daily_bucket_starts(from_at, to_at)
    bucket_index_by_start = {
        bucket_start: index for index, bucket_start in enumerate(bucket_starts_utc)
    }

    series_by_source: dict[int, dict[str, object]] = {}
    for row in rows:
        source_id = int(row["source_id"])
        bucket_start = row["bucket_start_paris"].astimezone(UTC)
        bucket_attack_count = int(row["bucket_attack_count"])

        if source_id not in series_by_source:
            series_by_source[source_id] = {
                "source_id": source_id,
                "source_name": row["source_name"],
                "source_color": row["source_color"],
                "source_is_active_current": row["source_is_active_current"],
                "attack_count": 0,
                "data": [0] * len(bucket_starts_utc),
            }

        series_entry = series_by_source[source_id]
        series_entry["attack_count"] = int(series_entry["attack_count"]) + bucket_attack_count

        bucket_index = bucket_index_by_start.get(bucket_start)
        if bucket_index is not None:
            series_entry["data"][bucket_index] = bucket_attack_count

    series = [
        AttackSourceTimeseriesSeriesSchema(**series_entry)
        for series_entry in series_by_source.values()
    ]

    return AttackSourceTimeseriesResponseSchema(
        from_at=from_at,
        to_at=to_at,
        bucket="day",
        total_attacks=total_attacks,
        bucket_starts_utc=bucket_starts_utc,
        series=series,
    )


@router.get("/by-type", response_model=TopAttackTypesResponseSchema)
def get_attack_distribution_by_type(
    from_at: datetime = Query(..., alias="from"),
    to_at: datetime = Query(..., alias="to"),
    statistics_repository: StatisticsRepository = Depends(get_statistics_repository),
) -> TopAttackTypesResponseSchema:
    """Retourne la repartition des attaques par type entre deux dates."""
    validate_datetime_range(from_at, to_at)
    logger.info(
        "endpoint=attacks_by_type event=requested from=%s to=%s",
        from_at,
        to_at,
    )
    rows = statistics_repository.get_attack_distribution_by_type(
        occurred_from=from_at,
        occurred_to=to_at,
    )
    items = [AttackTypePercentageSchema(**row) for row in rows]
    return TopAttackTypesResponseSchema(
        from_at=from_at,
        to_at=to_at,
        items=items,
    )
