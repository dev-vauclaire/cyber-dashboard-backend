"""Backwards-compatible secret service import for the API app."""

from __future__ import annotations

from cyber_dashboard_api._runtime import ensure_backend_root_on_path

ensure_backend_root_on_path()

from packages.common.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
    SecretServiceError,
)

__all__ = [
    "SecretConfigurationError",
    "SecretDecryptionError",
    "SecretService",
    "SecretServiceError",
]
