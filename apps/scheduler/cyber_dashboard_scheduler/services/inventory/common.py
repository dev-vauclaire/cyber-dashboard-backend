"""Utilitaires partagés pour l'inventaire des sources du scheduler."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
import logging
from typing import Any, TypeAlias

from packages.common.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)
from packages.database.repositories import SchedulerStateRepository, SourceRepository

from cyber_dashboard_scheduler.models import SourceOgo, SourceSerenicity
from cyber_dashboard_scheduler.utils import (
    NormalizationError,
    derive_color_random,
    require_hex_color,
)


SourceKey: TypeAlias = tuple[str, str]
InventorySource: TypeAlias = SourceOgo | SourceSerenicity


@dataclass(slots=True)
class InventoryConfigRunOutcome:
    """Résultat interne d'un inventaire pour une configuration donnée."""

    seen_source_keys: set[SourceKey] = field(default_factory=set)
    had_error: bool = False


def build_current_sources_by_key(
    rows: list[dict[str, Any]],
) -> dict[SourceKey, Mapping[str, Any]]:
    """Indexe les sources existantes par clé métier stable."""
    current_sources_by_key: dict[SourceKey, Mapping[str, Any]] = {}
    for row in rows:
        source_key = build_inventory_row_key(row)
        if source_key is not None:
            current_sources_by_key[source_key] = row
    return current_sources_by_key


def build_source_key(source: InventorySource) -> SourceKey:
    """Construit une clé stable pour comparer les sources entre deux runs."""
    if isinstance(source, SourceOgo):
        return (source.sensor_type_code, source.domain_name)
    return (source.sensor_type_code, source.external_id)


def build_inventory_row_key(row: Mapping[str, Any]) -> SourceKey | None:
    """Construit la clé stable d'une source lue depuis la base."""
    sensor_type_code = row.get("sensor_type_code")
    if not isinstance(sensor_type_code, str) or not sensor_type_code.strip():
        return None

    if isinstance(row.get("domain_name"), str) and row["domain_name"].strip():
        return (sensor_type_code, row["domain_name"].strip())

    if isinstance(row.get("external_id"), str) and row["external_id"].strip():
        return (sensor_type_code, row["external_id"].strip())

    return None


def derive_source_color(sensor_type_color: str, field_name: str) -> str:
    """Dérive une couleur de source à partir de la couleur du type de capteur."""
    try:
        return derive_color_random(require_hex_color(sensor_type_color, field_name))
    except ValueError as exc:
        raise NormalizationError(str(exc)) from exc


def decrypt_required_secret(
    *,
    secret_service: SecretService,
    config: Mapping[str, Any],
    field_name: str,
) -> str:
    """Déchiffre un secret obligatoire d'une configuration d'inventaire."""
    encrypted_value = config.get(field_name)
    if not isinstance(encrypted_value, str) or not encrypted_value.strip():
        raise RuntimeError(f"Champ de secret manquant : {field_name}")

    try:
        return secret_service.decrypt_secret(encrypted_value)
    except SecretConfigurationError as exc:
        raise RuntimeError(
            f"Impossible de charger la clé maître de chiffrement pour {field_name}"
        ) from exc
    except SecretDecryptionError as exc:
        raise RuntimeError(
            _build_secret_decryption_error_message(
                field_name=field_name,
                encrypted_value=encrypted_value,
            )
        ) from exc


def deactivate_missing_sources(
    *,
    logger: logging.Logger,
    source_repository: SourceRepository,
    scheduler_state_repository: SchedulerStateRepository,
    config_id: int,
    current_sources_by_key: Mapping[SourceKey, Mapping[str, Any]],
    seen_source_keys: set[SourceKey],
    inventory_timestamp: datetime,
    result: Any,
) -> bool:
    """Désactive les sources absentes du dernier inventaire."""
    had_error = False

    for source_key, source_row in current_sources_by_key.items():
        if source_key in seen_source_keys:
            continue
        if source_row.get("is_active") is False:
            continue

        source_id = int(source_row["source_id"])
        try:
            source_repository.deactivate_source(
                source_id=source_id,
                config_id=config_id,
            )
            scheduler_state_repository.mark_inventory_success(
                source_id=source_id,
                inventory_timestamp=inventory_timestamp,
            )
            result.sources_deactivated += 1
            logger.info(
                "Source désactivée car absente du dernier inventaire config=%s source_id=%s key=%s/%s",
                config_id,
                source_id,
                source_key[0],
                source_key[1],
            )
        except Exception as exc:
            result.source_errors += 1
            had_error = True
            logger.error(
                "Échec de la désactivation d'une source absente config=%s source_id=%s: %s",
                config_id,
                source_id,
                exc,
            )
            record_scheduler_state_error(
                logger=logger,
                scheduler_state_repository=scheduler_state_repository,
                source_id=source_id,
                inventory_timestamp=inventory_timestamp,
                error_message=str(exc),
            )

    return had_error


def record_known_source_error(
    *,
    logger: logging.Logger,
    scheduler_state_repository: SchedulerStateRepository,
    current_sources_by_key: Mapping[SourceKey, Mapping[str, Any]],
    source_key: SourceKey,
    inventory_timestamp: datetime,
    error_message: str,
) -> None:
    """Mémorise un échec d'inventaire sur une source déjà connue."""
    source_row = current_sources_by_key.get(source_key)
    if source_row is None:
        return

    record_scheduler_state_error(
        logger=logger,
        scheduler_state_repository=scheduler_state_repository,
        source_id=int(source_row["source_id"]),
        inventory_timestamp=inventory_timestamp,
        error_message=error_message,
    )


def record_scheduler_state_error(
    *,
    logger: logging.Logger,
    scheduler_state_repository: SchedulerStateRepository,
    source_id: int,
    inventory_timestamp: datetime,
    error_message: str,
) -> None:
    """Tente d'enregistrer un échec d'inventaire dans scheduler_state."""
    try:
        scheduler_state_repository.mark_inventory_failure(
            source_id=source_id,
            inventory_timestamp=inventory_timestamp,
            error_message=error_message[:1000],
        )
    except Exception as exc:
        logger.warning(
            "Impossible de mettre à jour scheduler_state en erreur source_id=%s: %s",
            source_id,
            exc,
        )


def _build_secret_decryption_error_message(
    *,
    field_name: str,
    encrypted_value: str,
) -> str:
    """Construit un message utile quand un secret stocké ne peut pas être déchiffré."""
    base_message = (
        f"Impossible de déchiffrer {field_name}; vérifier que l'API et le scheduler "
        "partagent la même clé maître de chiffrement"
    )

    if field_name == "encrypted_email" and "@" in encrypted_value:
        return (
            f"{base_message}. La valeur semble être un email stocké en clair dans une "
            "colonne chiffrée"
        )

    return base_message
