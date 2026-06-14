"""Collecte des attaques depuis le journal OGO V2."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import logging
from typing import Any

from packages.common.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)
from packages.database.repositories import (
    AttackRepository,
    AttacksCollectorConfigRepository,
    SchedulerStateRepository,
    SourceRepository,
)

from cyber_dashboard_scheduler.clients import OgoApiClient
from cyber_dashboard_scheduler.config import Settings
from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_scheduler.services.attack_normalization import normalize_ogo_journal_event
from cyber_dashboard_scheduler.services.collection_common import (
    build_collection_window,
    persist_collection_error,
    persist_collection_success,
)
from cyber_dashboard_scheduler.utils import NormalizationError


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class OgoAttackCollectionResult:
    """Résumé agrégé d'une collecte OGO."""

    sources_selected: int
    sources_succeeded: int
    source_errors: int
    pages_read: int
    events_read: int
    attacks_inserted: int
    attacks_ignored: int


class OgoAttackCollectionService:
    """Collecte les attaques depuis les sources OGO actives."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: PostgresDatabase,
        secret_service: SecretService,
        ogo_client: OgoApiClient,
    ) -> None:
        self._settings = settings
        self._database = database
        self._secret_service = secret_service
        self._ogo_client = ogo_client
        self._source_repository = SourceRepository(database)
        self._attack_repository = AttackRepository(database)
        self._scheduler_state_repository = SchedulerStateRepository(database)
        self._config_repository = AttacksCollectorConfigRepository(database)
        self._credentials_cache: dict[int, tuple[str, str]] = {}

    def collect_once(self) -> OgoAttackCollectionResult:
        """Collecte une fois le journal OGO pour toutes les sources actives."""
        sources = self._source_repository.list_active_ogo_sources_for_collection()
        if not sources:
            LOGGER.info("Aucune source OGO active à collecter")
            return OgoAttackCollectionResult(0, 0, 0, 0, 0, 0, 0)

        sources_succeeded = 0
        source_errors = 0
        pages_read = 0
        events_read = 0
        attacks_inserted = 0
        attacks_ignored = 0

        for source in sources:
            source_id = int(source["source_id"])
            domain_name = str(source["domain_name"])
            current_state = self._scheduler_state_repository.get_by_source_id(source_id)
            collection_window = build_collection_window(
                before=datetime.now(UTC),
                current_state=current_state,
                safety_window_seconds=self._settings.poll_safety_window_seconds,
            )

            LOGGER.info(
                "Collecte OGO démarrée source_id=%s domain=%s from=%s to=%s",
                source_id,
                domain_name,
                collection_window.after.isoformat(),
                collection_window.before.isoformat(),
            )

            try:
                organization_codes = _normalize_text_list(source.get("organization_codes"))
                if not organization_codes:
                    raise RuntimeError(
                        f"Aucun organization_code exploitable pour la source OGO {source_id}"
                    )

                email, api_key = self._get_credentials(
                    int(source["attacks_collector_config_id"])
                )
                source_pages_read = 0
                source_payloads: list[dict[str, Any]] = []

                for organization_code in organization_codes:
                    fetch_result = self._ogo_client.list_journal_events(
                        email=email,
                        api_key=api_key,
                        organization_code=organization_code,
                        after=collection_window.after,
                        before=collection_window.before,
                        sites=[domain_name],
                    )
                    source_pages_read += fetch_result.pages_read
                    source_payloads.extend(fetch_result.items)

                source_inserted, source_ignored = self._persist_attacks(
                    source_id=source_id,
                    domain_name=domain_name,
                    before=collection_window.before,
                    payloads=source_payloads,
                )
            except Exception as exc:
                source_errors += 1
                self._record_collection_error(
                    source_id=source_id,
                    current_state=current_state,
                    error=exc,
                )
                LOGGER.exception(
                    "Collecte OGO en erreur source_id=%s domain=%s: %s",
                    source_id,
                    domain_name,
                    exc,
                )
                continue

            sources_succeeded += 1
            pages_read += source_pages_read
            events_read += len(source_payloads)
            attacks_inserted += source_inserted
            attacks_ignored += source_ignored

            LOGGER.info(
                "Collecte OGO terminée source_id=%s domain=%s pages=%s lus=%s inserees=%s ignorees=%s",
                source_id,
                domain_name,
                source_pages_read,
                len(source_payloads),
                source_inserted,
                source_ignored,
            )

        result = OgoAttackCollectionResult(
            sources_selected=len(sources),
            sources_succeeded=sources_succeeded,
            source_errors=source_errors,
            pages_read=pages_read,
            events_read=events_read,
            attacks_inserted=attacks_inserted,
            attacks_ignored=attacks_ignored,
        )
        LOGGER.info(
            "Collecte OGO terminée sources=%s succes=%s erreurs=%s pages=%s lus=%s inserees=%s ignorees=%s",
            result.sources_selected,
            result.sources_succeeded,
            result.source_errors,
            result.pages_read,
            result.events_read,
            result.attacks_inserted,
            result.attacks_ignored,
        )
        return result

    def _persist_attacks(
        self,
        *,
        source_id: int,
        domain_name: str,
        before: datetime,
        payloads: list[dict[str, Any]],
    ) -> tuple[int, int]:
        success_timestamp = datetime.now(UTC)
        normalized_attacks: list[dict[str, Any]] = []
        attacks_ignored = 0

        for payload in payloads:
            try:
                attack = normalize_ogo_journal_event(
                    source_id=source_id,
                    payload=payload,
                    collected_at=success_timestamp,
                )
            except NormalizationError as exc:
                attacks_ignored += 1
                LOGGER.warning(
                    "Evenement OGO ignoré source_id=%s domain=%s raison=%s",
                    source_id,
                    domain_name,
                    exc,
                )
                continue

            if attack is None:
                attacks_ignored += 1
                continue

            normalized_attacks.append(asdict(attack))

        inserted_count, deduplicated_count = self._attack_repository.insert_collected_attacks(
            normalized_attacks
        )
        persist_collection_success(
            self._scheduler_state_repository,
            source_id=source_id,
            before=before,
            success_timestamp=success_timestamp,
        )
        return (inserted_count, attacks_ignored + deduplicated_count)

    def _record_collection_error(
        self,
        *,
        source_id: int,
        current_state: dict[str, Any] | None,
        error: Exception,
    ) -> None:
        try:
            persist_collection_error(
                self._scheduler_state_repository,
                source_id=source_id,
                current_state=current_state,
                error=error,
            )
        except Exception as exc:
            LOGGER.warning(
                "Impossible de mettre à jour scheduler_state en erreur pour la collecte OGO source_id=%s : %s",
                source_id,
                exc,
            )

    def _get_credentials(self, config_id: int) -> tuple[str, str]:
        cached_credentials = self._credentials_cache.get(config_id)
        if cached_credentials is not None:
            return cached_credentials

        config = self._config_repository.get_by_id(config_id)
        if config is None:
            raise RuntimeError(f"Configuration OGO introuvable: {config_id}")

        encrypted_email = config.get("encrypted_email")
        encrypted_api_key = config.get("encrypted_api_key")
        if not isinstance(encrypted_email, str) or not encrypted_email.strip():
            raise RuntimeError(f"Email OGO absent pour la configuration {config_id}")
        if not isinstance(encrypted_api_key, str) or not encrypted_api_key.strip():
            raise RuntimeError(f"Clé API OGO absente pour la configuration {config_id}")

        try:
            credentials = (
                self._secret_service.decrypt_secret(encrypted_email),
                self._secret_service.decrypt_secret(encrypted_api_key),
            )
        except (SecretConfigurationError, SecretDecryptionError) as exc:
            raise RuntimeError(
                f"Impossible de déchiffrer les secrets OGO de la configuration {config_id}"
            ) from exc

        self._credentials_cache[config_id] = credentials
        return credentials


def _normalize_text_list(value: Any) -> list[str]:
    """Normalise une liste de textes provenant de PostgreSQL."""
    if not isinstance(value, list):
        return []

    normalized_values: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if text:
            normalized_values.append(text)
    return normalized_values
