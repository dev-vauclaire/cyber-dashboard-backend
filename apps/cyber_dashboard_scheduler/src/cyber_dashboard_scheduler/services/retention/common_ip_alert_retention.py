"""Spécialisation de la rétention pour les alertes d'IP communes."""

from __future__ import annotations

from datetime import datetime

from cyber_dashboard_database.repositories import CommonIpAlertRepository

from cyber_dashboard_scheduler.db import PostgresDatabase


class CommonIpAlertRetentionService:
    """Supprime les alertes communes plus anciennes que la date limite calculée."""

    target_table = "common_ip_alerts"

    def __init__(self, database: PostgresDatabase) -> None:
        self._common_ip_alert_repository = CommonIpAlertRepository(database)

    def delete_before(self, *, date_limit: datetime) -> int:
        """Applique la politique de rétention sur `common_ip_alerts`."""
        return self._common_ip_alert_repository.delete_alerts_before(
            updated_before=date_limit
        )
