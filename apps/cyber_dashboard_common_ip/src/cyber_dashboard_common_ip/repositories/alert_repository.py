from __future__ import annotations

from psycopg import Connection

from cyber_dashboard_common_ip.domain.common_ip_alert import CommonIpAlert
from cyber_dashboard_common_ip.domain.common_ip_alert_source import CommonIpAlertSource
from cyber_dashboard_common_ip.db import PostgresDatabase
from cyber_dashboard_database.repositories import CommonIpAlertRepository


class AlertRepository:
    # Responsabilite : creer et mettre a jour les alertes d'IP communes dans la base.

    def __init__(self, database: PostgresDatabase) -> None:
        # Initialiser le repository des alertes.
        self._repository = CommonIpAlertRepository(database)

    def find_by_ip(
        self,
        attacker_ip: str,
        *,
        connection: Connection | None = None,
    ) -> CommonIpAlert | None:
        # Recuperer une alerte existante a partir d'une IP.
        record = self._repository.find_by_ip(attacker_ip, connection=connection)
        return CommonIpAlert.from_record(record) if record is not None else None

    def upsert_alert(
        self,
        alert: CommonIpAlert,
        *,
        connection: Connection | None = None,
    ) -> CommonIpAlert:
        # Creer ou mettre a jour une alerte principale.
        record = self._repository.upsert_alert(
            {
                "attacker_ip": alert.attacker_ip.normalize(),
                "first_seen_at": alert.first_seen_at,
                "last_seen_at": alert.last_seen_at,
                "distinct_source_count": alert.distinct_source_count,
                "status": alert.status,
            },
            connection=connection,
        )
        return CommonIpAlert.from_record(record)

    def upsert_alert_source(
        self,
        alert_source: CommonIpAlertSource,
        *,
        connection: Connection | None = None,
    ) -> None:
        # Creer ou mettre a jour l'association entre une alerte et une source.
        if alert_source.alert_id is None:
            raise ValueError("alert_id is required to persist an alert source")

        self._repository.upsert_alert_source(
            {
                "alert_id": alert_source.alert_id,
                "source_id": alert_source.source_id,
                "first_seen_at": alert_source.first_seen_at,
                "last_seen_at": alert_source.last_seen_at,
                "hit_count": alert_source.hit_count,
            },
            connection=connection,
        )
