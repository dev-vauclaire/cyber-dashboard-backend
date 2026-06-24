"""Backwards-compatible secret service import for the API app."""

from __future__ import annotations

from cyber_dashboard_common_tools.secret_service import (
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
