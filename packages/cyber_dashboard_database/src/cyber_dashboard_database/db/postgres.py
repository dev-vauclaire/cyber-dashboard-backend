"""Connexion PostgreSQL read-only pour l'API."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, Protocol

from psycopg import Connection, connect
from psycopg.rows import dict_row


class DatabaseSettingsProtocol(Protocol):
    """Contrat minimal attendu pour configurer PostgreSQL."""

    host: str
    port: int
    name: str
    user: str
    password: str


class PostgresDatabase:
    """Gere l'ouverture des connexions PostgreSQL."""

    def __init__(self, settings: DatabaseSettingsProtocol) -> None:
        self._settings = settings

    def open_connection(self) -> Connection:
        """Ouvre une connexion PostgreSQL avec lignes sous forme de dictionnaires."""
        return connect(
            host=self._settings.host,
            port=self._settings.port,
            dbname=self._settings.name,
            user=self._settings.user,
            password=self._settings.password,
            row_factory=dict_row,
        )

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        """Ouvre puis ferme proprement une connexion PostgreSQL."""
        connection = self.open_connection()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def read_only_connection(self) -> Iterator[Connection]:
        """Ouvre une connexion read-only pour les acces de l'API."""
        with self.connection() as connection:
            connection.read_only = True
            yield connection

    @contextmanager
    def transaction(self) -> Iterator[Connection]:
        """Encadre une transaction en ecriture avec commit ou rollback."""
        with self.connection() as connection:
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()

    @contextmanager
    def read_only_transaction(self) -> Iterator[Connection]:
        """Encadre une transaction read-only avec rollback final."""
        with self.read_only_connection() as connection:
            try:
                yield connection
            finally:
                connection.rollback()

    def fetch_all(
        self,
        query: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute une requete read-only et retourne toutes les lignes."""
        with self.read_only_transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def fetch_one(
        self,
        query: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Execute une requete read-only et retourne une seule ligne."""
        with self.read_only_transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def check_connection(self) -> None:
        """Verifie que PostgreSQL repond correctement."""
        with self.read_only_transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 AS ok")
                cursor.fetchone()
