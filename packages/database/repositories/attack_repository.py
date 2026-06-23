"""Lectures SQL pour les attaques."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Any

from psycopg.types.json import Jsonb

from packages.database.db import PostgresDatabase
from packages.database.models.enums import CorrelationStatus


class AttackRepository:
    """Expose les lectures sur les attaques et leurs filtres."""

    def __init__(self, database: PostgresDatabase) -> None:
        self._database = database

    def _build_filter_clause(
        self,
        *,
        source_id: int | None = None,
        sensor_type_code: str | None = None,
        attack_type: str | None = None,
        occurred_from: datetime | None = None,
        occurred_to: datetime | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Construit dynamiquement la clause WHERE selon les filtres fournis."""
        clauses: list[str] = []
        params: dict[str, Any] = {}

        if source_id is not None:
            clauses.append("a.source_id = %(source_id)s")
            params["source_id"] = source_id

        if sensor_type_code is not None:
            clauses.append("st.code = %(sensor_type_code)s")
            params["sensor_type_code"] = sensor_type_code

        if attack_type is not None:
            clauses.append("a.attack_type = %(attack_type)s")
            params["attack_type"] = attack_type

        if occurred_from is not None:
            clauses.append("a.occurred_at >= %(occurred_from)s")
            params["occurred_from"] = occurred_from

        if occurred_to is not None:
            clauses.append("a.occurred_at <= %(occurred_to)s")
            params["occurred_to"] = occurred_to

        if not clauses:
            return "", params

        return "WHERE " + " AND ".join(clauses), params

    def list_attacks(
        self,
        *,
        limit: int,
        offset: int,
        source_id: int | None = None,
        sensor_type_code: str | None = None,
        attack_type: str | None = None,
        occurred_from: datetime | None = None,
        occurred_to: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Retourne une liste paginee d'attaques avec filtres optionnels."""
        where_clause, params = self._build_filter_clause(
            source_id=source_id,
            sensor_type_code=sensor_type_code,
            attack_type=attack_type,
            occurred_from=occurred_from,
            occurred_to=occurred_to,
        )

        query = f"""
            SELECT
                a.id,
                a.source_id,
                s.name AS source_name,
                st.code AS sensor_type_code,
                a.attacker_ip::TEXT AS attacker_ip,
                a.occurred_at,
                a.collected_at,
                a.attack_type
            FROM attacks a
            INNER JOIN sources s
                ON s.id = a.source_id
            INNER JOIN sensor_types st
                ON st.id = s.sensor_type_id
            {where_clause}
            ORDER BY a.occurred_at DESC, a.id DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset
        return self._database.fetch_all(query, params)

    def count_attacks(
        self,
        *,
        source_id: int | None = None,
        sensor_type_code: str | None = None,
        attack_type: str | None = None,
        occurred_from: datetime | None = None,
        occurred_to: datetime | None = None,
    ) -> int:
        """Compte les attaques selon les memes filtres que la liste paginee."""
        where_clause, params = self._build_filter_clause(
            source_id=source_id,
            sensor_type_code=sensor_type_code,
            attack_type=attack_type,
            occurred_from=occurred_from,
            occurred_to=occurred_to,
        )

        query = f"""
            SELECT COUNT(*)::INT AS total
            FROM attacks a
            INNER JOIN sources s
                ON s.id = a.source_id
            INNER JOIN sensor_types st
                ON st.id = s.sensor_type_id
            {where_clause}
        """
        row = self._database.fetch_one(query, params)
        return 0 if row is None else int(row["total"])

    def insert_collected_attacks(
        self, attacks: list[dict[str, Any]]
    ) -> tuple[int, int]:
        """Insere un lot d'attaques collectees en une seule transaction."""
        if not attacks:
            return (0, 0)

        query = """
            INSERT INTO attacks (
                deduplication_id,
                source_id,
                source_event_id,
                attacker_ip,
                occurred_at,
                collected_at,
                attack_type,
                raw_payload,
                correlation_status
            )
            VALUES (
                %(deduplication_id)s,
                %(source_id)s,
                %(source_event_id)s,
                %(attacker_ip)s,
                %(occurred_at)s,
                %(collected_at)s,
                %(attack_type)s,
                %(raw_payload)s,
                %(correlation_status)s
            )
            ON CONFLICT (deduplication_id) DO NOTHING
            RETURNING id
        """

        inserted_count = 0
        ignored_count = 0
        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                for attack in attacks:
                    deduplication_id = _build_deduplication_id(
                        source_id=int(attack["source_id"]),
                        attacker_ip=str(attack["attacker_ip"]),
                        occurred_at=attack["occurred_at"],
                    )
                    cursor.execute(
                        query,
                        {
                            "deduplication_id": deduplication_id,
                            "source_id": attack["source_id"],
                            "source_event_id": attack.get("source_event_id"),
                            "attacker_ip": attack["attacker_ip"],
                            "occurred_at": attack["occurred_at"],
                            "collected_at": attack["collected_at"],
                            "attack_type": attack.get("attack_type"),
                            "raw_payload": (
                                Jsonb(attack["raw_payload"])
                                if attack.get("raw_payload") is not None
                                else None
                            ),
                            "correlation_status": CorrelationStatus.PENDING.value,
                        },
                    )
                    if cursor.fetchone() is None:
                        ignored_count += 1
                    else:
                        inserted_count += 1

        return (inserted_count, ignored_count)

    def delete_attacks_before(self, *, occurred_before: datetime) -> int:
        """Supprime les attaques plus anciennes qu'une date limite."""
        query = """
            DELETE FROM attacks
            WHERE occurred_at < %(occurred_before)s
        """
        with self._database.transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, {"occurred_before": occurred_before})
                return cursor.rowcount


def _build_deduplication_id(
    *,
    source_id: int,
    attacker_ip: str,
    occurred_at: datetime,
) -> str:
    """Construit la cle idempotente d'une attaque collectee."""
    digest = sha256(
        f"{source_id}|{attacker_ip}|{occurred_at.isoformat()}".encode("utf-8")
    )
    return digest.hexdigest()
