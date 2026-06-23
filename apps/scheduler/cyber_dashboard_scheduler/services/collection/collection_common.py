"""Aides partagées pour les collectes d'attaques."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from packages.database.repositories import SchedulerStateRepository


@dataclass(frozen=True, slots=True)
class CollectionWindow:
    """Fenêtre temporelle UTC utilisée pour interroger une source."""

    after: datetime
    before: datetime


def build_collection_window(
    *,
    before: datetime,
    current_state: Mapping[str, Any] | None,
    safety_window_seconds: int,
) -> CollectionWindow:
    """Construit la fenêtre de collecte à partir de `last_poll_at`."""
    safety_window = timedelta(seconds=safety_window_seconds)
    last_poll_at = (
        current_state.get("last_poll_at") if current_state is not None else None
    )
    base_after = (
        last_poll_at
        if isinstance(last_poll_at, datetime)
        else before - timedelta(hours=24)
    )
    after = base_after - safety_window
    if after >= before:
        after = before - timedelta(seconds=1)
    return CollectionWindow(after=after, before=before)


def persist_collection_success(
    scheduler_state_repository: SchedulerStateRepository,
    *,
    source_id: int,
    before: datetime,
    success_timestamp: datetime,
) -> None:
    """Enregistre un succès de collecte dans `scheduler_state`."""
    scheduler_state_repository.mark_collection_success(
        source_id=source_id,
        last_poll_at=before,
        success_timestamp=success_timestamp,
    )


def persist_collection_error(
    scheduler_state_repository: SchedulerStateRepository,
    *,
    source_id: int,
    current_state: Mapping[str, Any] | None,
    error: Exception,
    error_timestamp: datetime | None = None,
) -> None:
    """Enregistre un échec de collecte dans `scheduler_state`."""
    last_poll_at = None
    if current_state is not None and isinstance(
        current_state.get("last_poll_at"), datetime
    ):
        last_poll_at = current_state["last_poll_at"]

    scheduler_state_repository.mark_collection_failure(
        source_id=source_id,
        last_poll_at=last_poll_at,
        error_timestamp=error_timestamp or datetime.now(UTC),
        error_message=str(error)[:1000],
    )
