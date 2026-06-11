"""Schemas de reponse pour les statistiques d'attaques."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field

from .common import ApiSchema


class AttackSummaryResponseSchema(ApiSchema):
    """Resume du volume d'attaques sur une periode."""

    from_at: datetime
    to_at: datetime
    total_attacks: int


class AttackSourcePercentageSchema(ApiSchema):
    """Part des attaques pour une source sur une periode."""

    source_id: int
    source_name: str
    attack_count: int
    percentage: float


class AttackStatisticsResponseSchema(ApiSchema):
    """Statistiques d'attaques par source sur une periode."""

    from_at: datetime
    to_at: datetime
    total_attacks: int
    by_source: list[AttackSourcePercentageSchema]


class AttackTypePercentageSchema(ApiSchema):
    """Part des attaques pour un type d'attaque sur une periode."""

    attack_type: str
    attack_count: int
    percentage: float


class TopAttackTypesResponseSchema(ApiSchema):
    """Top des types d'attaques sur une periode."""

    from_at: datetime
    to_at: datetime
    items: list[AttackTypePercentageSchema]


class AttackSourceTimeseriesSeriesSchema(ApiSchema):
    """Serie journaliere des attaques pour une source."""

    source_id: int
    source_name: str
    source_color: str
    source_is_active_current: bool
    attack_count: int
    data: list[int]


class AttackSourceTimeseriesResponseSchema(ApiSchema):
    """Serie temporelle journaliere des attaques par source."""

    model_config = ConfigDict(populate_by_name=True)

    from_at: datetime = Field(serialization_alias="from")
    to_at: datetime = Field(serialization_alias="to")
    bucket: Literal["day"]
    total_attacks: int
    bucket_starts_utc: list[datetime]
    series: list[AttackSourceTimeseriesSeriesSchema]
