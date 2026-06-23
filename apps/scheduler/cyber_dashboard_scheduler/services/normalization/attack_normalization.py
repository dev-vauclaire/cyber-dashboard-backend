"""Normalisation des attaques externes vers le format interne du scheduler."""

from __future__ import annotations

from typing import Any, Mapping

from cyber_dashboard_scheduler.models import Attack
from cyber_dashboard_scheduler.utils.normalization import (
    copy_payload,
    normalize_collected_at,
    normalize_datetime_to_utc,
    optional_text,
    require_ip,
    require_mapping,
    to_bool,
)


def normalize_serenicity_sensor_flux(
    *,
    source_id: int,
    payload: Mapping[str, Any],
    collected_at: Any = None,
) -> Attack | None:
    """Normalise un flux Serenicity de type detoxio."""
    if not to_bool(payload.get("toxic")):
        return None

    return Attack(
        source_id=source_id,
        source_event_id=_optional_source_event_id(payload),
        attacker_ip=require_ip(payload.get("ip1"), "ip1"),
        occurred_at=normalize_datetime_to_utc(
            payload.get("start_of_hour"), "start_of_hour"
        ),
        collected_at=normalize_collected_at(collected_at),
        attack_type=optional_text(payload.get("protocol")),
        raw_payload=copy_payload(payload),
    )


def normalize_lurio_report(
    *,
    source_id: int,
    payload: Mapping[str, Any],
    collected_at: Any = None,
) -> Attack:
    """Normalise un report Lurio."""
    threat_payload = require_mapping(payload.get("threat") or {}, "threat")

    return Attack(
        source_id=source_id,
        source_event_id=_optional_source_event_id(payload, threat_payload),
        attacker_ip=require_ip(payload.get("ip"), "ip"),
        occurred_at=normalize_datetime_to_utc(payload.get("created_at"), "created_at"),
        collected_at=normalize_collected_at(collected_at),
        attack_type=optional_text(threat_payload.get("type")),
        raw_payload=copy_payload(payload),
    )


def normalize_ogo_journal_event(
    *,
    source_id: int,
    payload: Mapping[str, Any],
    collected_at: Any = None,
) -> Attack | None:
    """Normalise un evenement SECURITY du journal OGO V2."""
    event_payload = require_mapping(payload.get("event"), "event")
    attack_type = optional_text(payload.get("subtype")) or optional_text(
        payload.get("subtypeLabel")
    )

    return Attack(
        source_id=source_id,
        source_event_id=_optional_source_event_id(payload, event_payload),
        attacker_ip=require_ip(event_payload.get("ip"), "event.ip"),
        occurred_at=normalize_datetime_to_utc(payload.get("date"), "date"),
        collected_at=normalize_collected_at(collected_at),
        attack_type=attack_type,
        raw_payload=copy_payload(payload),
    )


def _optional_source_event_id(*payloads: Mapping[str, Any]) -> str | None:
    """Extrait un identifiant d'evenement optionnel depuis plusieurs payloads."""
    for payload in payloads:
        for key in ("id", "event_id", "uid"):
            value = payload.get(key)
            if value is None:
                continue

            normalized_value = str(value).strip()
            if normalized_value:
                return normalized_value

    return None
