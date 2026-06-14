"""Service d'orchestration de la rétention des données du scheduler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import logging

from packages.database.repositories import RetentionPolicyRepository

from cyber_dashboard_scheduler.db import PostgresDatabase
from cyber_dashboard_scheduler.services.retention import (
    AttackRetentionService,
    CommonIpAlertRetentionService,
)


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetentionRunResult:
    """Résumé d'un run de rétention."""

    policies_selected: int = 0
    policies_succeeded: int = 0
    policies_failed: int = 0
    rows_deleted: int = 0


class RetentionService:
    """Exécute les politiques de rétention actives table par table."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._retention_policy_repository = RetentionPolicyRepository(database)
        self._handlers = {
            AttackRetentionService.target_table: AttackRetentionService(database),
            CommonIpAlertRetentionService.target_table: CommonIpAlertRetentionService(
                database
            ),
        }

    def run_once(self) -> RetentionRunResult:
        """Applique une passe de rétention sur chaque politique active."""
        run_timestamp = datetime.now(UTC)
        policies = self._retention_policy_repository.list_active_policies()
        result = RetentionRunResult(policies_selected=len(policies))

        LOGGER.info(
            "Début de la rétention scheduler. policies_selectionnees=%s",
            result.policies_selected,
        )

        for policy in policies:
            target_table = str(policy["target_table"])
            retention_days = int(policy["retention_days"])
            date_limit = run_timestamp - timedelta(days=retention_days)

            try:
                if retention_days <= 0:
                    raise ValueError("retention_days doit être strictement positif")

                if not self._retention_policy_repository.target_table_exists(
                    target_table=target_table
                ):
                    raise RuntimeError(
                        f"La table cible `{target_table}` est introuvable en base"
                    )

                handler = self._handlers.get(target_table)
                if handler is None:
                    raise RuntimeError(
                        f"Aucun service de rétention n'est implémenté pour `{target_table}`"
                    )

                deleted_count = handler.delete_before(date_limit=date_limit)
                self._retention_policy_repository.mark_run_success(
                    target_table=target_table,
                    run_timestamp=run_timestamp,
                    deleted_count=deleted_count,
                )
                result = RetentionRunResult(
                    policies_selected=result.policies_selected,
                    policies_succeeded=result.policies_succeeded + 1,
                    policies_failed=result.policies_failed,
                    rows_deleted=result.rows_deleted + deleted_count,
                )
                LOGGER.info(
                    "Rétention réussie target_table=%s retention_days=%s date_limit=%s deleted=%s",
                    target_table,
                    retention_days,
                    date_limit.isoformat(),
                    deleted_count,
                )
            except Exception as exc:
                self._retention_policy_repository.mark_run_failure(
                    target_table=target_table,
                    run_timestamp=run_timestamp,
                    error_message=str(exc),
                )
                result = RetentionRunResult(
                    policies_selected=result.policies_selected,
                    policies_succeeded=result.policies_succeeded,
                    policies_failed=result.policies_failed + 1,
                    rows_deleted=result.rows_deleted,
                )
                LOGGER.exception(
                    "Rétention en erreur target_table=%s retention_days=%s: %s",
                    target_table,
                    retention_days,
                    exc,
                )

        LOGGER.info(
            "Rétention scheduler terminée. policies_ok=%s policies_ko=%s lignes_supprimees=%s",
            result.policies_succeeded,
            result.policies_failed,
            result.rows_deleted,
        )
        return result
