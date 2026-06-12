"""Ecritures SQL des alertes d'IP communes pour le correlateur."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from psycopg import Connection

from packages.database.db import PostgresDatabase


class CommonIpAlertRepository:
    """Expose les operations SQL sur common_ip_alerts et common_ip_alert_sources."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def find_by_ip(
        self,
        attacker_ip: str,
        *,
        connection: Connection | None = None,
    ) -> dict[str, Any] | None:
        """Retourne une alerte existante pour une IP donnee."""
        query = """
            SELECT
                id,
                HOST(attacker_ip) AS attacker_ip,
                first_seen_at,
                last_seen_at,
                distinct_source_count,
                status
            FROM common_ip_alerts
            WHERE HOST(attacker_ip) = %(attacker_ip)s
        """
        with self._cursor(connection) as cursor:
            cursor.execute(query, {"attacker_ip": attacker_ip})
            row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def upsert_alert(
        self,
        payload: dict[str, Any],
        *,
        connection: Connection | None = None,
    ) -> dict[str, Any]:
        """Cree ou met a jour une alerte principale."""
        query = """
            INSERT INTO common_ip_alerts (
                attacker_ip,
                first_seen_at,
                last_seen_at,
                distinct_source_count,
                status
            )
            VALUES (
                %(attacker_ip)s,
                %(first_seen_at)s,
                %(last_seen_at)s,
                %(distinct_source_count)s,
                %(status)s
            )
            ON CONFLICT (attacker_ip) DO UPDATE
            SET first_seen_at = LEAST(common_ip_alerts.first_seen_at, EXCLUDED.first_seen_at),
                last_seen_at = GREATEST(common_ip_alerts.last_seen_at, EXCLUDED.last_seen_at),
                distinct_source_count = EXCLUDED.distinct_source_count,
                status = EXCLUDED.status,
                updated_at = NOW()
            RETURNING
                id,
                HOST(attacker_ip) AS attacker_ip,
                first_seen_at,
                last_seen_at,
                distinct_source_count,
                status
        """
        with self._cursor(connection) as cursor:
            cursor.execute(query, payload)
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert common IP alert")
        return dict(row)

    def upsert_alert_source(
        self,
        payload: dict[str, Any],
        *,
        connection: Connection | None = None,
    ) -> None:
        """Cree ou met a jour l'association entre une alerte et une source."""
        query = """
            INSERT INTO common_ip_alert_sources (
                alert_id,
                source_id,
                first_seen_at,
                last_seen_at,
                hit_count
            )
            VALUES (
                %(alert_id)s,
                %(source_id)s,
                %(first_seen_at)s,
                %(last_seen_at)s,
                %(hit_count)s
            )
            ON CONFLICT (alert_id, source_id) DO UPDATE
            SET first_seen_at = EXCLUDED.first_seen_at,
                last_seen_at = EXCLUDED.last_seen_at,
                hit_count = EXCLUDED.hit_count
        """
        with self._cursor(connection) as cursor:
            cursor.execute(query, payload)

    @contextmanager
    def _cursor(
        self,
        connection: Connection | None = None,
    ) -> Iterator[Any]:
        """Expose un curseur adosse a une connexion existante ou a une transaction locale."""
        if connection is not None:
            with connection.cursor() as cursor:
                yield cursor
            return

        with self._database.transaction() as managed_connection:
            with managed_connection.cursor() as cursor:
                yield cursor
