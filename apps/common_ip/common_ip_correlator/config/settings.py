from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal runtime environments.
    def load_dotenv(*args, **kwargs) -> bool:
        return False

ENV_FILE_PATH = Path(__file__).resolve().parents[2] / ".env"
VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


class ConfigurationError(ValueError):
    """Levee quand une variable d'environnement obligatoire est absente ou invalide."""


def _load_env_file() -> None:
    load_dotenv(dotenv_path=ENV_FILE_PATH, override=False)


def _require_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip():
            return value.strip()
    env_names = ", ".join(names)
    raise ConfigurationError(
        f"Missing required environment variable. Expected one of: {env_names}"
    )


def _get_env(*names: str, default: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip():
            return value.strip()
    return default


def _get_positive_int(*names: str, default: int) -> int:
    raw_value = _get_env(*names, default=str(default))
    try:
        parsed_value = int(raw_value)
    except ValueError as exc:
        env_names = ", ".join(names)
        raise ConfigurationError(
            f"Invalid integer value for environment variable {env_names}: {raw_value}"
        ) from exc

    if parsed_value <= 0:
        env_names = ", ".join(names)
        raise ConfigurationError(
            f"Environment variable {env_names} must be a positive integer"
        )
    return parsed_value


def _get_non_negative_int(*names: str, default: int) -> int:
    raw_value = _get_env(*names, default=str(default))
    try:
        parsed_value = int(raw_value)
    except ValueError as exc:
        env_names = ", ".join(names)
        raise ConfigurationError(
            f"Invalid integer value for environment variable {env_names}: {raw_value}"
        ) from exc

    if parsed_value < 0:
        env_names = ", ".join(names)
        raise ConfigurationError(
            f"Environment variable {env_names} must be greater than or equal to zero"
        )
    return parsed_value


def _read_bool_env(*names: str, default: bool = False) -> bool:
    truthy_values = {"1", "true", "yes", "on"}
    falsy_values = {"0", "false", "no", "off"}

    for name in names:
        value = os.getenv(name)
        if value is None:
            continue

        normalized_value = value.strip().lower()
        if normalized_value in truthy_values:
            return True
        if normalized_value in falsy_values:
            return False
        raise ConfigurationError(f"Invalid boolean value for {name}: {value}")

    return default


def _get_log_level(name: str, default: str) -> str:
    value = _get_env(name, default=default).upper()
    if value not in VALID_LOG_LEVELS:
        allowed_values = ", ".join(sorted(VALID_LOG_LEVELS))
        raise ConfigurationError(
            f"Invalid log level for {name}: {value}. Expected one of: {allowed_values}"
        )
    return value


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    """Parametres de connexion PostgreSQL du correlateur."""

    host: str
    port: int
    name: str
    user: str
    password: str


@dataclass(frozen=True, slots=True)
class CorrelatorConfig:
    """Configuration racine du worker de correlation."""

    database: DatabaseSettings
    batch_size: int = 500
    poll_interval_seconds: int = 10
    log_level: str = "INFO"
    compute_average_processing_time: bool = False

    @classmethod
    def from_env(cls) -> "CorrelatorConfig":
        _load_env_file()
        return cls(
            database=DatabaseSettings(
                host=_require_env("DB_HOST", "CORRELATOR_DB_HOST", "POSTGRES_HOST", "PGHOST"),
                port=_get_positive_int(
                    "DB_PORT",
                    "CORRELATOR_DB_PORT",
                    "POSTGRES_PORT",
                    "PGPORT",
                    default=5432,
                ),
                name=_require_env("DB_NAME", "CORRELATOR_DB_NAME", "POSTGRES_DB", "PGDATABASE"),
                user=_require_env("DB_USER", "CORRELATOR_DB_USER", "POSTGRES_USER", "PGUSER"),
                password=_require_env(
                    "DB_PASSWORD",
                    "CORRELATOR_DB_PASSWORD",
                    "POSTGRES_PASSWORD",
                    "PGPASSWORD",
                ),
            ),
            batch_size=_get_positive_int("CORRELATOR_BATCH_SIZE", default=500),
            poll_interval_seconds=_get_non_negative_int(
                "CORRELATOR_POLL_INTERVAL_SECONDS",
                default=10,
            ),
            log_level=_get_log_level("CORRELATOR_LOG_LEVEL", "INFO"),
            compute_average_processing_time=_read_bool_env(
                "CORRELATOR_COMPUTE_AVERAGE_PROCESSING_TIME",
                default=False,
            ),
        )

    def validate(self) -> None:
        if not self.database.host:
            raise ConfigurationError("Database host must not be empty")
        if not self.database.name:
            raise ConfigurationError("Database name must not be empty")
        if not self.database.user:
            raise ConfigurationError("Database user must not be empty")
        if not self.database.password:
            raise ConfigurationError("Database password must not be empty")
        if self.database.port <= 0:
            raise ConfigurationError("Database port must be a positive integer")
        if self.batch_size <= 0:
            raise ConfigurationError("Batch size must be a positive integer")
        if self.poll_interval_seconds < 0:
            raise ConfigurationError("Poll interval must be greater than or equal to zero")


@lru_cache(maxsize=1)
def get_settings() -> CorrelatorConfig:
    """Expose une configuration memoisee pour toute l'application."""
    settings = CorrelatorConfig.from_env()
    settings.validate()
    return settings
