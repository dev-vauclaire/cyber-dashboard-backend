"""Acces base de donnees."""

from .dependencies import build_get_database
from .postgres import DatabaseSettingsProtocol, PostgresDatabase

__all__ = ["DatabaseSettingsProtocol", "PostgresDatabase", "build_get_database"]
