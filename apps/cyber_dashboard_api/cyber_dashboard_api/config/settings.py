"""Chargement simple de la configuration via les variables d'environnement."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

from dotenv import load_dotenv


ENV_FILE_PATH = Path(__file__).resolve().parents[2] / ".env"
VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


class ConfigurationError(ValueError):
    """Levee quand une variable d'environnement obligatoire est absente."""


def _load_env_file() -> None:
    """Charge le fichier .env local s'il est present."""
    load_dotenv(dotenv_path=ENV_FILE_PATH, override=False)


def _require_env(name: str) -> str:
    """Retourne une variable obligatoire non vide."""
    value = os.getenv(name)
    if value is None or not value.strip():
        raise ConfigurationError(
            f"Variable d'environnement obligatoire manquante : {name}"
        )
    return value.strip()


def _get_env(name: str, default: str) -> str:
    """Retourne une variable optionnelle avec valeur par defaut."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _get_positive_int(name: str, default: int) -> int:
    """Retourne un entier positif avec valeur par defaut."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        parsed_value = int(value)
    except ValueError as exc:
        raise ConfigurationError(
            f"Valeur entiere invalide pour la variable d'environnement {name} : {value}"
        ) from exc

    if parsed_value <= 0:
        raise ConfigurationError(
            f"La variable d'environnement {name} doit etre un entier positif"
        )

    return parsed_value


def _get_positive_float(name: str, default: float) -> float:
    """Retourne un flottant strictement positif avec valeur par defaut."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        parsed_value = float(value)
    except ValueError as exc:
        raise ConfigurationError(
            f"Valeur decimale invalide pour la variable d'environnement {name} : {value}"
        ) from exc

    if parsed_value <= 0:
        raise ConfigurationError(
            f"La variable d'environnement {name} doit etre un nombre strictement positif"
        )

    return parsed_value


def _get_non_negative_float(name: str, default: float) -> float:
    """Retourne un flottant positif ou nul avec valeur par defaut."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        parsed_value = float(value)
    except ValueError as exc:
        raise ConfigurationError(
            f"Valeur decimale invalide pour la variable d'environnement {name} : {value}"
        ) from exc

    if parsed_value < 0:
        raise ConfigurationError(
            f"La variable d'environnement {name} doit etre un nombre positif ou nul"
        )

    return parsed_value


def _get_log_level(name: str, default: str) -> str:
    """Retourne un niveau de log valide."""
    value = _get_env(name, default).upper()
    if value not in VALID_LOG_LEVELS:
        allowed_values = ", ".join(sorted(VALID_LOG_LEVELS))
        raise ConfigurationError(
            f"Niveau de log invalide pour la variable d'environnement {name} : {value}. "
            f"Valeurs attendues : {allowed_values}"
        )
    return value


def _get_optional_env(name: str) -> str | None:
    """Retourne une variable optionnelle nettoyee ou None."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _get_path_prefixes(name: str) -> tuple[str, ...]:
    """Retourne une liste de prefixes de chemins HTTP depuis une variable CSV."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return ()

    prefixes: list[str] = []
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        if not item.startswith("/"):
            item = f"/{item}"
        prefixes.append(item)

    return tuple(prefixes)


def _get_public_ip(name: str, default: str) -> str:
    """Retourne une IP publique valide pour les validations externes."""
    raw_value = _get_env(name, default)
    try:
        parsed_ip = ip_address(raw_value)
    except ValueError as exc:
        raise ConfigurationError(
            f"Adresse IP invalide pour la variable d'environnement {name} : {raw_value}"
        ) from exc

    if (
        parsed_ip.is_private
        or parsed_ip.is_loopback
        or parsed_ip.is_link_local
        or parsed_ip.is_multicast
        or parsed_ip.is_reserved
        or parsed_ip.is_unspecified
    ):
        raise ConfigurationError(
            f"La variable d'environnement {name} doit contenir une IP publique routable"
        )

    return str(parsed_ip)


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    """Parametres de connexion PostgreSQL."""

    host: str
    port: int
    name: str
    user: str
    password: str


@dataclass(frozen=True, slots=True)
class SecretSettings:
    """Parametres de chargement de la cle maitre de chiffrement."""

    secret_key_file: str | None
    secret_key: str | None


@dataclass(frozen=True, slots=True)
class ValidationSettings:
    """Parametres de validation des integrations externes."""

    timeout_seconds: float
    test_ip: str
    ogo_base_url: str | None
    serenicity_base_url: str | None


@dataclass(frozen=True, slots=True)
class Settings:
    """Configuration racine de l'API."""

    api_name: str
    api_host: str
    api_port: int
    api_log_level: str
    api_dev_response_delay_seconds: float
    api_dev_response_delay_paths: tuple[str, ...]
    database: DatabaseSettings
    secrets: SecretSettings
    validation: ValidationSettings

    @classmethod
    def from_env(cls) -> "Settings":
        """Construit les parametres depuis l'environnement."""
        _load_env_file()

        return cls(
            api_name=_get_env("API_NAME", "Cyber Dashboard API"),
            api_host=_get_env("API_HOST", "127.0.0.1"),
            api_port=_get_positive_int("API_PORT", 8000),
            api_log_level=_get_log_level("API_LOG_LEVEL", "INFO"),
            api_dev_response_delay_seconds=_get_non_negative_float(
                "API_DEV_RESPONSE_DELAY_SECONDS",
                0.0,
            ),
            api_dev_response_delay_paths=_get_path_prefixes(
                "API_DEV_RESPONSE_DELAY_PATHS"
            ),
            database=DatabaseSettings(
                host=_require_env("DB_HOST"),
                port=_get_positive_int("DB_PORT", 5432),
                name=_require_env("DB_NAME"),
                user=_require_env("DB_USER"),
                password=_require_env("DB_PASSWORD"),
            ),
            secrets=SecretSettings(
                secret_key_file=_get_optional_env("CYBER_DASHBOARD_SECRET_KEY_FILE"),
                secret_key=_get_optional_env("CYBER_DASHBOARD_SECRET_KEY"),
            ),
            validation=ValidationSettings(
                timeout_seconds=_get_positive_float(
                    "CYBER_DASHBOARD_VALIDATION_TIMEOUT_SECONDS",
                    5.0,
                ),
                test_ip=_get_public_ip(
                    "CYBER_DASHBOARD_VALIDATION_TEST_IP",
                    "8.8.8.8",
                ),
                ogo_base_url=_get_optional_env("OGO_BASE_URL"),
                serenicity_base_url=_get_optional_env("SERENICITY_BASE_URL"),
            ),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Expose une configuration memoisee pour toute l'application."""
    return Settings.from_env()
