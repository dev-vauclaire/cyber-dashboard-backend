"""Collecte des attaques depuis les leurres Lurio Serenicity."""

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

from cyber_dashboard_scheduler.clients import SerenicityLurioClient
from cyber_dashboard_scheduler.config import Settings
from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_scheduler.services.attack_normalization import normalize_lurio_report
from cyber_dashboard_scheduler.services.collection_common import (
    build_collection_window,
    persist_collection_error,
    persist_collection_success,
)
from cyber_dashboard_scheduler.utils import NormalizationError


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LurioAttackCollectionResult:
    """Résumé agrégé d'une collecte Lurio."""

    sources_selected: int
    sources_succeeded: int
    source_errors: int
    pages_read: int
    reports_read: int
    attacks_inserted: int
    attacks_ignored: int


class LurioAttackCollectionService:
    """Collecte les attaques depuis les sources actives de type lurio."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: PostgresDatabase,
        secret_service: SecretService,
    ) -> None:
        self._settings = settings
        self._database = database
        self._secret_service = secret_service
        self._source_repository = SourceRepository(database)
        self._attack_repository = AttackRepository(database)
        self._scheduler_state_repository = SchedulerStateRepository(database)
        self._config_repository = AttacksCollectorConfigRepository(database)
        self._api_key_cache: dict[int, str] = {}
        self._client_cache: dict[int, SerenicityLurioClient] = {}

    def collect_once(self) -> LurioAttackCollectionResult:
        """Collecte une fois les reports Lurio pour toutes les sources actives."""
        sources = [
            row
            for row in self._source_repository.list_active_serenicity_sources_for_collection()
            if row.get("sensor_type_code") == "lurio"
        ]
        if not sources:
            LOGGER.info("Aucune source lurio active à collecter")
            return LurioAttackCollectionResult(0, 0, 0, 0, 0, 0, 0)

        sources_succeeded = 0
        source_errors = 0
        pages_read = 0
        reports_read = 0
        attacks_inserted = 0
        attacks_ignored = 0

        for source in sources:
            source_id = int(source["source_id"])
            external_id = str(source["external_id"])
            current_state = self._scheduler_state_repository.get_by_source_id(source_id)
            collection_window = build_collection_window(
                before=datetime.now(UTC),
                current_state=current_state,
                safety_window_seconds=self._settings.poll_safety_window_seconds,
            )

            LOGGER.info(
                "Collecte Lurio démarrée source_id=%s external_id=%s from=%s to=%s",
                source_id,
                external_id,
                collection_window.after.isoformat(),
                collection_window.before.isoformat(),
            )

            try:
                client = self._get_client(int(source["attacks_collector_config_id"]))
                fetch_result = client.list_lurio_reports(
                    lurio_id=external_id,
                    from_datetime=collection_window.after,
                    to_datetime=collection_window.before,
                )
                source_inserted, source_ignored = self._persist_attacks(
                    source_id=source_id,
                    external_id=external_id,
                    before=collection_window.before,
                    payloads=fetch_result.items,
                    collection_completed=fetch_result.is_complete,
                    last_report_created_at=fetch_result.last_report_created_at,
                )
            except Exception as exc:
                source_errors += 1
                self._record_collection_error(
                    source_id=source_id,
                    current_state=current_state,
                    error=exc,
                )
                LOGGER.exception(
                    "Collecte Lurio en erreur source_id=%s external_id=%s: %s",
                    source_id,
                    external_id,
                    exc,
                )
                continue

            sources_succeeded += 1
            pages_read += fetch_result.pages_read
            reports_read += len(fetch_result.items)
            attacks_inserted += source_inserted
            attacks_ignored += source_ignored

            LOGGER.info(
                "Collecte Lurio terminée source_id=%s external_id=%s pages=%s lus=%s inserees=%s ignorees=%s",
                source_id,
                external_id,
                fetch_result.pages_read,
                len(fetch_result.items),
                source_inserted,
                source_ignored,
            )

        result = LurioAttackCollectionResult(
            sources_selected=len(sources),
            sources_succeeded=sources_succeeded,
            source_errors=source_errors,
            pages_read=pages_read,
            reports_read=reports_read,
            attacks_inserted=attacks_inserted,
            attacks_ignored=attacks_ignored,
        )
        LOGGER.info(
            "Collecte Lurio terminée sources=%s succes=%s erreurs=%s pages=%s lus=%s inserees=%s ignorees=%s",
            result.sources_selected,
            result.sources_succeeded,
            result.source_errors,
            result.pages_read,
            result.reports_read,
            result.attacks_inserted,
            result.attacks_ignored,
        )
        return result

    def _persist_attacks(
        self,
        *,
        source_id: int,
        external_id: str,
        before: datetime,
        payloads: list[dict[str, Any]],
        collection_completed: bool,
        last_report_created_at: datetime | None,
    ) -> tuple[int, int]:
        success_timestamp = datetime.now(UTC)
        normalized_attacks: list[dict[str, Any]] = []
        attacks_ignored = 0

        for payload in payloads:
            try:
                attack = normalize_lurio_report(
                    source_id=source_id,
                    payload=payload,
                    collected_at=success_timestamp,
                )
            except NormalizationError as exc:
                attacks_ignored += 1
                LOGGER.warning(
                    "Report Lurio ignoré source_id=%s external_id=%s raison=%s",
                    source_id,
                    external_id,
                    exc,
                )
                continue

            normalized_attacks.append(asdict(attack))

        inserted_count, deduplicated_count = self._attack_repository.insert_collected_attacks(
            normalized_attacks
        )
        poll_cursor = before if collection_completed else last_report_created_at
        if poll_cursor is not None:
            persist_collection_success(
                self._scheduler_state_repository,
                source_id=source_id,
                before=poll_cursor,
                success_timestamp=success_timestamp,
            )

        if not collection_completed:
            LOGGER.warning(
                "Collecte Lurio incomplète source_id=%s external_id=%s last_poll_at=%s",
                source_id,
                external_id,
                last_report_created_at.isoformat() if last_report_created_at else "inconnu",
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
                "Impossible de mettre à jour scheduler_state en erreur pour la collecte Lurio source_id=%s : %s",
                source_id,
                exc,
            )

    def _get_client(self, config_id: int) -> SerenicityLurioClient:
        client = self._client_cache.get(config_id)
        if client is not None:
            return client

        api_key = self._get_api_key(config_id)
        client = SerenicityLurioClient(
            base_url=self._settings.serenicity.base_url,
            api_key=api_key,
            timeout_seconds=self._settings.http_timeout_seconds,
        )
        self._client_cache[config_id] = client
        return client

    def _get_api_key(self, config_id: int) -> str:
        cached_api_key = self._api_key_cache.get(config_id)
        if cached_api_key is not None:
            return cached_api_key

        config = self._config_repository.get_by_id(config_id)
        if config is None:
            raise RuntimeError(f"Configuration Serenicity introuvable: {config_id}")

        encrypted_api_key = config.get("encrypted_api_key")
        if not isinstance(encrypted_api_key, str) or not encrypted_api_key.strip():
            raise RuntimeError(
                f"Clé API Serenicity absente pour la configuration {config_id}"
            )

        try:
            api_key = self._secret_service.decrypt_secret(encrypted_api_key)
        except (SecretConfigurationError, SecretDecryptionError) as exc:
            raise RuntimeError(
                f"Impossible de déchiffrer la clé API Serenicity de la configuration {config_id}"
            ) from exc

        self._api_key_cache[config_id] = api_key
        return api_key
