"""Service d'inventaire des sources base sur attacks_collector_config."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
from typing import Any, Mapping, TypeAlias

from packages.common.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)
from packages.database.repositories import (
    AttacksCollectorConfigRepository,
    SchedulerStateRepository,
    SensorTypeRepository,
    SourceRepository,
)

from cyber_dashboard_scheduler.clients import (
    ApiClientError,
    OgoApiClient,
    SerenicityLurioClient,
    SerenicitySensorClient,
)
from cyber_dashboard_scheduler.config import Settings
from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_scheduler.models import SourceOgo, SourceSerenicity
from cyber_dashboard_scheduler.services.normalization.source_normalization import (
    normalize_lurio_source,
    normalize_serenicity_sensor,
)
from cyber_dashboard_scheduler.utils import (
    NormalizationError,
    derive_color_random,
    require_hex_color,
    require_text,
)


LOGGER = logging.getLogger(__name__)
SourceKey: TypeAlias = tuple[str, str]
InventorySource: TypeAlias = SourceOgo | SourceSerenicity
SerenicitySensorClientFactory: TypeAlias = Callable[[str], SerenicitySensorClient]
SerenicityLurioClientFactory: TypeAlias = Callable[[str], SerenicityLurioClient]


@dataclass(slots=True)
class InventoryRunResult:
    """Résumé d'un run d'inventaire."""

    configs_selected: int = 0
    configs_succeeded: int = 0
    configs_failed: int = 0
    endpoints_called: list[str] = field(default_factory=list)
    sources_detected: int = 0
    sources_persisted: int = 0
    sources_deactivated: int = 0
    sources_skipped: int = 0
    source_errors: int = 0


class SourceInventoryService:
    """Orchestre l'inventaire des sources a partir des configurations actives."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: PostgresDatabase,
        secret_service: SecretService,
        ogo_client: OgoApiClient,
        serenicity_sensor_client_factory: SerenicitySensorClientFactory,
        serenicity_lurio_client_factory: SerenicityLurioClientFactory,
    ) -> None:
        self._settings = settings
        self._database = database
        self._secret_service = secret_service
        self._ogo_client = ogo_client
        self._serenicity_sensor_client_factory = serenicity_sensor_client_factory
        self._serenicity_lurio_client_factory = serenicity_lurio_client_factory
        self._config_repository = AttacksCollectorConfigRepository(database)
        self._sensor_type_repository = SensorTypeRepository(database)
        self._source_repository = SourceRepository(database)
        self._scheduler_state_repository = SchedulerStateRepository(database)

    def run_once(self) -> InventoryRunResult:
        """Exécute un inventaire complet des configurations demandées."""
        inventory_timestamp = datetime.now(UTC)
        result = InventoryRunResult()
        sensor_type_colors = self._load_sensor_type_colors()
        configs = self._config_repository.list_active_inventory_requested_configs()
        result.configs_selected = len(configs)

        LOGGER.info(
            "Début de l'inventaire scheduler. configs_selectionnees=%s types_supportes=%s",
            result.configs_selected,
            ", ".join(sorted(sensor_type_colors)) or "aucun",
        )

        for config in configs:
            collector_type = str(config["collector_type"])
            config_id = int(config["id"])
            LOGGER.info(
                "Inventaire de la configuration id=%s type=%s name=%s",
                config_id,
                collector_type,
                config["name"],
            )
            if collector_type == "ogo":
                is_success = self._run_ogo_inventory(
                    config=config,
                    sensor_type_colors=sensor_type_colors,
                    inventory_timestamp=inventory_timestamp,
                    result=result,
                )
            elif collector_type == "serenicity":
                is_success = self._run_serenicity_inventory(
                    config=config,
                    sensor_type_colors=sensor_type_colors,
                    inventory_timestamp=inventory_timestamp,
                    result=result,
                )
            else:
                LOGGER.error(
                    "Type de collecteur non supporté pour l'inventaire id=%s type=%s",
                    config_id,
                    collector_type,
                )
                is_success = False

            if is_success:
                self._config_repository.clear_inventory_request(config_id=config_id)
                result.configs_succeeded += 1
                LOGGER.info(
                    "Inventaire terminé avec succès pour la configuration id=%s",
                    config_id,
                )
            else:
                result.configs_failed += 1
                LOGGER.warning(
                    "Inventaire partiel ou en erreur pour la configuration id=%s. "
                    "inventory_requested reste à TRUE pour un retry futur.",
                    config_id,
                )

        LOGGER.info(
            "Inventaire scheduler terminé. configs_ok=%s configs_ko=%s detectees=%s persistees=%s desactivees=%s ignorees=%s erreurs=%s",
            result.configs_succeeded,
            result.configs_failed,
            result.sources_detected,
            result.sources_persisted,
            result.sources_deactivated,
            result.sources_skipped,
            result.source_errors,
        )
        return result

    def _load_sensor_type_colors(self) -> dict[str, str]:
        rows = self._sensor_type_repository.list_sensor_types()
        return {
            str(row["code"]): str(row["color"])
            for row in rows
            if row.get("code") is not None and row.get("color") is not None
        }

    def _run_ogo_inventory(
        self,
        *,
        config: Mapping[str, Any],
        sensor_type_colors: Mapping[str, str],
        inventory_timestamp: datetime,
        result: InventoryRunResult,
    ) -> bool:
        if "waf" not in sensor_type_colors:
            LOGGER.error("Type de capteur waf absent de sensor_types")
            return False

        # On récupère les sources déjà présentes (si il y en a) dans la base pour cette configuration
        current_sources = self._source_repository.list_sources_for_inventory(
            config_id=int(config["id"])
        )
        
        current_sources_by_key: dict[SourceKey, Mapping[str, Any]] = {}
        for source in current_sources:
            source_key = _build_inventory_row_key(source)
            if source_key is not None:
                current_sources_by_key[source_key] = source
        seen_source_keys: set[SourceKey] = set()
        had_error = False

        try:
            email = self._decrypt_required_secret(
                config=config,
                field_name="encrypted_email",
            )
            api_key = self._decrypt_required_secret(
                config=config,
                field_name="encrypted_api_key",
            )
        except RuntimeError as exc:
            LOGGER.error("Configuration OGO invalide id=%s: %s", config["id"], exc)
            return False

        endpoint = "GET /v2/organizations"
        result.endpoints_called.append(endpoint)
        try:
            organizations = self._ogo_client.list_organizations(
                email=email,
                api_key=api_key,
                lang="fr",
            )
        except ApiClientError as exc:
            LOGGER.error("Échec de l'appel OGO %s pour config=%s: %s", endpoint, config["id"], exc)
            return False

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
                had_error = True
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

                seen_source_keys.add(_build_source_key(source))
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
                color=_derive_source_color(sensor_type_colors["waf"], "waf.color"),
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
                had_error = True
                LOGGER.error(
                    "Échec de persistance de la source OGO config=%s domain=%s: %s",
                    config["id"],
                    domain_name,
                    exc,
                )
                self._record_known_source_error(
                    current_sources_by_key=current_sources_by_key,
                    source_key=("waf", domain_name),
                    inventory_timestamp=inventory_timestamp,
                    error_message=str(exc),
                )

        had_error = self._deactivate_missing_sources(
            config_id=int(config["id"]),
            current_sources_by_key=current_sources_by_key,
            seen_source_keys=seen_source_keys,
            inventory_timestamp=inventory_timestamp,
            result=result,
        ) or had_error

        return not had_error

    def _run_serenicity_inventory(
        self,
        *,
        config: Mapping[str, Any],
        sensor_type_colors: Mapping[str, str],
        inventory_timestamp: datetime,
        result: InventoryRunResult,
    ) -> bool:
        supported_codes = {
            code for code in ("detoxio", "lurio") if code in sensor_type_colors
        }
        if not supported_codes:
            LOGGER.error("Aucun type Serenicity supporté n'est présent dans sensor_types")
            return False

        current_sources = self._source_repository.list_sources_for_inventory(
            config_id=int(config["id"])
        )
        current_sources_by_key: dict[SourceKey, Mapping[str, Any]] = {}
        for source in current_sources:
            source_key = _build_inventory_row_key(source)
            if source_key is not None:
                current_sources_by_key[source_key] = source
        seen_source_keys: set[SourceKey] = set()
        had_error = False

        try:
            api_key = self._decrypt_required_secret(
                config=config,
                field_name="encrypted_api_key",
            )
        except RuntimeError as exc:
            LOGGER.error(
                "Configuration Serenicity invalide id=%s: %s",
                config["id"],
                exc,
            )
            return False

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
                had_error = True
            else:
                had_error = self._persist_serenicity_payloads(
                    config=config,
                    payloads=sensor_payloads,
                    normalizer=lambda payload: normalize_serenicity_sensor(
                        payload,
                        sensor_type_colors,
                    ),
                    supported_sensor_types=supported_codes,
                    current_sources_by_key=current_sources_by_key,
                    seen_source_keys=seen_source_keys,
                    inventory_timestamp=inventory_timestamp,
                    result=result,
                ) or had_error

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
                had_error = True
            else:
                had_error = self._persist_serenicity_payloads(
                    config=config,
                    payloads=lurio_payloads,
                    normalizer=lambda payload: normalize_lurio_source(
                        payload,
                        sensor_type_colors["lurio"],
                    ),
                    supported_sensor_types=supported_codes,
                    current_sources_by_key=current_sources_by_key,
                    seen_source_keys=seen_source_keys,
                    inventory_timestamp=inventory_timestamp,
                    result=result,
                ) or had_error

        had_error = self._deactivate_missing_sources(
            config_id=int(config["id"]),
            current_sources_by_key=current_sources_by_key,
            seen_source_keys=seen_source_keys,
            inventory_timestamp=inventory_timestamp,
            result=result,
        ) or had_error

        return not had_error

    def _persist_serenicity_payloads(
        self,
        *,
        config: Mapping[str, Any],
        payloads: list[dict[str, Any]],
        normalizer: Any,
        supported_sensor_types: set[str],
        current_sources_by_key: Mapping[SourceKey, Mapping[str, Any]],
        seen_source_keys: set[SourceKey],
        inventory_timestamp: datetime,
        result: InventoryRunResult,
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

            seen_source_keys.add(_build_source_key(source))
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
                self._record_known_source_error(
                    current_sources_by_key=current_sources_by_key,
                    source_key=_build_source_key(source),
                    inventory_timestamp=inventory_timestamp,
                    error_message=str(exc),
                )

        return had_error

    def _deactivate_missing_sources(
        self,
        *,
        config_id: int,
        current_sources_by_key: Mapping[SourceKey, Mapping[str, Any]],
        seen_source_keys: set[SourceKey],
        inventory_timestamp: datetime,
        result: InventoryRunResult,
    ) -> bool:
        had_error = False

        for source_key, source_row in current_sources_by_key.items():
            if source_key in seen_source_keys:
                continue
            if source_row.get("is_active") is False:
                continue

            source_id = int(source_row["source_id"])
            try:
                self._source_repository.deactivate_source(
                    source_id=source_id,
                    config_id=config_id,
                )
                self._scheduler_state_repository.mark_inventory_success(
                    source_id=source_id,
                    inventory_timestamp=inventory_timestamp,
                )
                result.sources_deactivated += 1
                LOGGER.info(
                    "Source desactivee car absente du dernier inventaire config=%s source_id=%s key=%s/%s",
                    config_id,
                    source_id,
                    source_key[0],
                    source_key[1],
                )
            except Exception as exc:
                result.source_errors += 1
                had_error = True
                LOGGER.error(
                    "Échec de la désactivation d'une source absente config=%s source_id=%s: %s",
                    config_id,
                    source_id,
                    exc,
                )
                self._record_scheduler_state_error(
                    source_id=source_id,
                    inventory_timestamp=inventory_timestamp,
                    error_message=str(exc),
                )

        return had_error

    def _decrypt_required_secret(
        self,
        *,
        config: Mapping[str, Any],
        field_name: str,
    ) -> str:
        encrypted_value = config.get(field_name)
        if not isinstance(encrypted_value, str) or not encrypted_value.strip():
            raise RuntimeError(f"Champ de secret manquant : {field_name}")

        try:
            return self._secret_service.decrypt_secret(encrypted_value)
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

    def _record_known_source_error(
        self,
        *,
        current_sources_by_key: Mapping[SourceKey, Mapping[str, Any]],
        source_key: SourceKey,
        inventory_timestamp: datetime,
        error_message: str,
    ) -> None:
        source_row = current_sources_by_key.get(source_key)
        if source_row is None:
            return

        self._record_scheduler_state_error(
            source_id=int(source_row["source_id"]),
            inventory_timestamp=inventory_timestamp,
            error_message=error_message,
        )

    def _record_scheduler_state_error(
        self,
        *,
        source_id: int,
        inventory_timestamp: datetime,
        error_message: str,
    ) -> None:
        try:
            self._scheduler_state_repository.mark_inventory_failure(
                source_id=source_id,
                inventory_timestamp=inventory_timestamp,
                error_message=error_message[:1000],
            )
        except Exception as exc:
            LOGGER.warning(
                "Impossible de mettre à jour scheduler_state en erreur source_id=%s: %s",
                source_id,
                exc,
            )


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
        color=_derive_source_color(sensor_type_color, "waf.color"),
    )


def _derive_source_color(sensor_type_color: str, field_name: str) -> str:
    """Dérive une couleur de source à partir de la couleur du type de capteur."""
    try:
        return derive_color_random(require_hex_color(sensor_type_color, field_name))
    except ValueError as exc:
        raise NormalizationError(str(exc)) from exc


def _build_secret_decryption_error_message(
    *,
    field_name: str,
    encrypted_value: str,
) -> str:
    """Construit un message utile quand un secret stocke ne peut pas etre dechiffre."""
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


def _build_source_key(source: InventorySource) -> SourceKey:
    """Construit une clé stable pour comparer les sources entre deux runs."""
    if isinstance(source, SourceOgo):
        return (source.sensor_type_code, source.domain_name)
    return (source.sensor_type_code, source.external_id)


def _build_inventory_row_key(row: Mapping[str, Any]) -> SourceKey | None:
    """Construit la clé stable d'une source lue depuis la base."""
    sensor_type_code = row.get("sensor_type_code")
    if not isinstance(sensor_type_code, str) or not sensor_type_code.strip():
        return None

    if isinstance(row.get("domain_name"), str) and row["domain_name"].strip():
        return (sensor_type_code, row["domain_name"].strip())

    if isinstance(row.get("external_id"), str) and row["external_id"].strip():
        return (sensor_type_code, row["external_id"].strip())

    return None
