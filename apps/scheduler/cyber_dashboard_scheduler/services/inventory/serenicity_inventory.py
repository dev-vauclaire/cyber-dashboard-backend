"""Inventaire des sources Serenicity à partir des configurations actives."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
import logging
from typing import Any, TypeAlias

from packages.common.secret_service import SecretService
from packages.database.repositories import SchedulerStateRepository, SourceRepository

from cyber_dashboard_scheduler.clients import (
    ApiClientError,
    SerenicityLurioClient,
    SerenicitySensorClient,
)
from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_scheduler.models import SourceSerenicity
from cyber_dashboard_scheduler.services.inventory.common import (
    InventoryConfigRunOutcome,
    SourceKey,
    build_source_key,
    decrypt_required_secret,
    record_known_source_error,
)
from cyber_dashboard_scheduler.services.normalization.source_normalization import (
    normalize_lurio_source,
    normalize_serenicity_sensor,
)
from cyber_dashboard_scheduler.utils import NormalizationError

LOGGER = logging.getLogger(__name__)
SerenicitySensorClientFactory: TypeAlias = Callable[[str], SerenicitySensorClient]
SerenicityLurioClientFactory: TypeAlias = Callable[[str], SerenicityLurioClient]


class SerenicityInventoryService:
    """Gère l'inventaire des sources Serenicity pour une configuration donnée."""

    def __init__(
        self,
        *,
        database: PostgresDatabase,
        secret_service: SecretService,
        serenicity_sensor_client_factory: SerenicitySensorClientFactory,
        serenicity_lurio_client_factory: SerenicityLurioClientFactory,
    ) -> None:
        self._secret_service = secret_service
        self._serenicity_sensor_client_factory = serenicity_sensor_client_factory
        self._serenicity_lurio_client_factory = serenicity_lurio_client_factory
        self._source_repository = SourceRepository(database)
        self._scheduler_state_repository = SchedulerStateRepository(database)

    def run_config(
        self,
        *,
        config: Mapping[str, Any],
        sensor_type_colors: Mapping[str, str],
        current_sources_by_key: Mapping[SourceKey, Mapping[str, Any]],
        inventory_timestamp: datetime,
        result: Any,
    ) -> InventoryConfigRunOutcome:
        """Exécute l'inventaire Serenicity d'une configuration."""
        supported_codes = {
            code for code in ("detoxio", "lurio") if code in sensor_type_colors
        }
        if not supported_codes:
            LOGGER.error(
                "Aucun type Serenicity supporté n'est présent dans sensor_types"
            )
            return InventoryConfigRunOutcome(had_error=True)

        try:
            api_key = decrypt_required_secret(
                secret_service=self._secret_service,
                config=config,
                field_name="encrypted_api_key",
            )
        except RuntimeError as exc:
            LOGGER.error(
                "Configuration Serenicity invalide id=%s: %s",
                config["id"],
                exc,
            )
            return InventoryConfigRunOutcome(had_error=True)

        outcome = InventoryConfigRunOutcome()
        sensor_client = self._serenicity_sensor_client_factory(api_key)
        lurio_client = self._serenicity_lurio_client_factory(api_key)

        if "detoxio" in supported_codes:
            endpoint = "GET /api/v1/sensors"
            result.endpoints_called.append(endpoint)
            try:
                sensor_payloads = sensor_client.list_sensors()
            except ApiClientError as exc:
                LOGGER.error(
                    "Échec de l'appel Serenicity %s pour config=%s: %s",
                    endpoint,
                    config["id"],
                    exc,
                )
                outcome.had_error = True
            else:
                outcome.had_error = (
                    self._persist_payloads(
                        config=config,
                        payloads=sensor_payloads,
                        normalizer=lambda payload: normalize_serenicity_sensor(
                            payload,
                            sensor_type_colors,
                        ),
                        supported_sensor_types=supported_codes,
                        current_sources_by_key=current_sources_by_key,
                        seen_source_keys=outcome.seen_source_keys,
                        inventory_timestamp=inventory_timestamp,
                        result=result,
                    )
                    or outcome.had_error
                )

        if "lurio" in supported_codes:
            endpoint = "GET /api/v1/lurios"
            result.endpoints_called.append(endpoint)
            try:
                lurio_payloads = lurio_client.list_lurios()
            except ApiClientError as exc:
                LOGGER.error(
                    "Échec de l'appel Serenicity %s pour config=%s: %s",
                    endpoint,
                    config["id"],
                    exc,
                )
                outcome.had_error = True
            else:
                outcome.had_error = (
                    self._persist_payloads(
                        config=config,
                        payloads=lurio_payloads,
                        normalizer=lambda payload: normalize_lurio_source(
                            payload,
                            sensor_type_colors["lurio"],
                        ),
                        supported_sensor_types=supported_codes,
                        current_sources_by_key=current_sources_by_key,
                        seen_source_keys=outcome.seen_source_keys,
                        inventory_timestamp=inventory_timestamp,
                        result=result,
                    )
                    or outcome.had_error
                )

        return outcome

    def _persist_payloads(
        self,
        *,
        config: Mapping[str, Any],
        payloads: list[dict[str, Any]],
        normalizer: Callable[[dict[str, Any]], SourceSerenicity],
        supported_sensor_types: set[str],
        current_sources_by_key: Mapping[SourceKey, Mapping[str, Any]],
        seen_source_keys: set[SourceKey],
        inventory_timestamp: datetime,
        result: Any,
    ) -> bool:
        had_error = False

        for payload in payloads:
            result.sources_detected += 1
            try:
                source = normalizer(payload)
            except NormalizationError as exc:
                result.sources_skipped += 1
                LOGGER.warning(
                    "Source Serenicity ignorée pour config=%s: %s",
                    config["id"],
                    exc,
                )
                continue

            if source.sensor_type_code not in supported_sensor_types:
                result.sources_skipped += 1
                LOGGER.info(
                    "Source Serenicity ignorée car type non supporté config=%s type=%s external_id=%s",
                    config["id"],
                    source.sensor_type_code,
                    source.external_id,
                )
                continue

            seen_source_keys.add(build_source_key(source))
            try:
                persisted_source = self._source_repository.upsert_serenicity_source(
                    config_id=int(config["id"]),
                    sensor_type_code=source.sensor_type_code,
                    external_id=source.external_id,
                    source_name=source.name,
                    is_active=source.is_active,
                    default_color=source.color,
                    latitude=source.latitude,
                    longitude=source.longitude,
                )
                self._scheduler_state_repository.mark_inventory_success(
                    source_id=int(persisted_source["source_id"]),
                    inventory_timestamp=inventory_timestamp,
                )
                result.sources_persisted += 1
            except Exception as exc:
                result.source_errors += 1
                had_error = True
                LOGGER.error(
                    "Échec de persistance de la source Serenicity config=%s type=%s external_id=%s: %s",
                    config["id"],
                    source.sensor_type_code,
                    source.external_id,
                    exc,
                )
                record_known_source_error(
                    logger=LOGGER,
                    scheduler_state_repository=self._scheduler_state_repository,
                    current_sources_by_key=current_sources_by_key,
                    source_key=build_source_key(source),
                    inventory_timestamp=inventory_timestamp,
                    error_message=str(exc),
                )

        return had_error
