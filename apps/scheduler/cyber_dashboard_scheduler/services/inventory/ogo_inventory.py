"""Inventaire des sources OGO à partir des configurations actives."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import logging
from typing import Any

from packages.common.secret_service import SecretService
from packages.database.repositories import SchedulerStateRepository, SourceRepository

from cyber_dashboard_scheduler.clients import ApiClientError, OgoApiClient
from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_scheduler.models import SourceOgo
from cyber_dashboard_scheduler.services.inventory.common import (
    InventoryConfigRunOutcome,
    SourceKey,
    build_source_key,
    decrypt_required_secret,
    derive_source_color,
    record_known_source_error,
)
from cyber_dashboard_scheduler.utils import NormalizationError, require_text


LOGGER = logging.getLogger(__name__)


class OgoInventoryService:
    """Gère l'inventaire des sources OGO pour une configuration donnée."""

    def __init__(
        self,
        *,
        database: PostgresDatabase,
        secret_service: SecretService,
        ogo_client: OgoApiClient,
    ) -> None:
        self._secret_service = secret_service
        self._ogo_client = ogo_client
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
        """Exécute l'inventaire OGO d'une configuration."""
        if "waf" not in sensor_type_colors:
            LOGGER.error("Type de capteur waf absent de sensor_types")
            return InventoryConfigRunOutcome(had_error=True)

        try:
            email = decrypt_required_secret(
                secret_service=self._secret_service,
                config=config,
                field_name="encrypted_email",
            )
            api_key = decrypt_required_secret(
                secret_service=self._secret_service,
                config=config,
                field_name="encrypted_api_key",
            )
        except RuntimeError as exc:
            LOGGER.error("Configuration OGO invalide id=%s: %s", config["id"], exc)
            return InventoryConfigRunOutcome(had_error=True)

        outcome = InventoryConfigRunOutcome()
        endpoint = "GET /v2/organizations"
        result.endpoints_called.append(endpoint)

        try:
            organizations = self._ogo_client.list_organizations(
                email=email,
                api_key=api_key,
                lang="fr",
            )
        except ApiClientError as exc:
            LOGGER.error(
                "Échec de l'appel OGO %s pour config=%s: %s",
                endpoint,
                config["id"],
                exc,
            )
            outcome.had_error = True
            return outcome

        domains_to_organizations: dict[str, set[str]] = {}
        for organization_payload in organizations:
            organization_mapping = organization_payload.get("organization")
            if not isinstance(organization_mapping, Mapping):
                LOGGER.warning(
                    "Organisation OGO ignorée car payload invalide pour config=%s",
                    config["id"],
                )
                continue

            try:
                organization_code = require_text(
                    organization_mapping.get("code"),
                    "organization.code",
                )
            except NormalizationError as exc:
                LOGGER.warning(
                    "Organisation OGO ignorée car code invalide pour config=%s: %s",
                    config["id"],
                    exc,
                )
                continue

            sites_endpoint = f"GET /v2/organizations/{organization_code}/sites"
            result.endpoints_called.append(sites_endpoint)
            try:
                sites = self._ogo_client.list_sites(
                    email=email,
                    api_key=api_key,
                    organization_code=organization_code,
                    lang="fr",
                )
            except ApiClientError as exc:
                LOGGER.error(
                    "Échec de l'appel OGO %s pour config=%s: %s",
                    sites_endpoint,
                    config["id"],
                    exc,
                )
                outcome.had_error = True
                continue

            for site_payload in sites:
                result.sources_detected += 1
                try:
                    source = _normalize_ogo_domain_source(
                        site_payload=site_payload,
                        sensor_type_color=sensor_type_colors["waf"],
                    )
                except NormalizationError as exc:
                    result.sources_skipped += 1
                    LOGGER.warning(
                        "Site OGO ignoré pour config=%s: %s",
                        config["id"],
                        exc,
                    )
                    continue

                outcome.seen_source_keys.add(build_source_key(source))
                domains_to_organizations.setdefault(source.domain_name, set()).add(
                    organization_code
                )

        for domain_name in sorted(domains_to_organizations):
            source = SourceOgo(
                sensor_type_code="waf",
                domain_name=domain_name,
                organization_codes=sorted(domains_to_organizations[domain_name]),
                name=domain_name,
                is_active=True,
                color=derive_source_color(sensor_type_colors["waf"], "waf.color"),
            )
            try:
                persisted_source = self._source_repository.upsert_ogo_source(
                    config_id=int(config["id"]),
                    sensor_type_code=source.sensor_type_code,
                    domain_name=source.domain_name,
                    source_name=source.name,
                    is_active=source.is_active,
                    default_color=source.color,
                    organization_codes=source.organization_codes,
                )
                self._scheduler_state_repository.mark_inventory_success(
                    source_id=int(persisted_source["source_id"]),
                    inventory_timestamp=inventory_timestamp,
                )
                result.sources_persisted += 1
            except Exception as exc:
                result.source_errors += 1
                outcome.had_error = True
                LOGGER.error(
                    "Échec de persistance de la source OGO config=%s domain=%s: %s",
                    config["id"],
                    domain_name,
                    exc,
                )
                record_known_source_error(
                    logger=LOGGER,
                    scheduler_state_repository=self._scheduler_state_repository,
                    current_sources_by_key=current_sources_by_key,
                    source_key=("waf", domain_name),
                    inventory_timestamp=inventory_timestamp,
                    error_message=str(exc),
                )

        return outcome


def _normalize_ogo_domain_source(
    *,
    site_payload: Mapping[str, Any],
    sensor_type_color: str,
) -> SourceOgo:
    """Normalise un domaine OGO renvoyé par `/v2/organizations/{code}/sites`."""
    domain_name = require_text(site_payload.get("domainName"), "domainName")
    return SourceOgo(
        sensor_type_code="waf",
        domain_name=domain_name,
        organization_codes=[],
        name=domain_name,
        is_active=True,
        color=derive_source_color(sensor_type_color, "waf.color"),
    )
