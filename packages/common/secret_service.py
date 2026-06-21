"""Shared secret encryption utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

try:
    from cryptography.fernet import Fernet, InvalidToken
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception


class SecretSettingsProtocol(Protocol):
    """Minimal settings contract required by the secret service."""

    secret_key_file: str | None
    secret_key: str | None


class SecretServiceError(RuntimeError):
    """Generic secret service error."""


class SecretConfigurationError(SecretServiceError):
    """Raised when the encryption master key is misconfigured."""


class SecretDecryptionError(SecretServiceError):
    """Raised when a stored secret cannot be decrypted."""


class SecretService:
    """Encrypts, decrypts and builds hints for stored secrets."""

    def __init__(self, settings: SecretSettingsProtocol) -> None:
        self._settings = settings
        self._fernet: Fernet | None = None

    def _read_key_value(self) -> str:
        """Read the encryption key from a file or from the environment."""
        env_key_value = self._read_env_key_value()

        if self._settings.secret_key_file:
            try:
                key_value = Path(self._settings.secret_key_file).read_text(
                    encoding="utf-8"
                ).strip()
            except OSError as exc:
                if env_key_value is not None:
                    return env_key_value
                raise SecretConfigurationError(
                    "Impossible de lire CYBER_DASHBOARD_SECRET_KEY_FILE"
                ) from exc

            if key_value:
                return key_value
            if env_key_value is not None:
                return env_key_value
            raise SecretConfigurationError(
                "CYBER_DASHBOARD_SECRET_KEY_FILE est vide"
            )

        if env_key_value is not None:
            return env_key_value

        raise SecretConfigurationError(
            "La clé maître de chiffrement n'est pas configurée. "
            "Définissez CYBER_DASHBOARD_SECRET_KEY_FILE ou CYBER_DASHBOARD_SECRET_KEY"
        )

    def _read_env_key_value(self) -> str | None:
        """Read the encryption key directly from the environment if present."""
        if self._settings.secret_key and self._settings.secret_key.strip():
            return self._settings.secret_key.strip()
        return None

    def _get_fernet(self) -> Fernet:
        """Initialize Fernet only when needed."""
        if Fernet is None:
            raise SecretConfigurationError(
                "La dépendance 'cryptography' est requise pour le chiffrement des secrets"
            )

        if self._fernet is None:
            key_value = self._read_key_value()
            try:
                self._fernet = Fernet(key_value.encode("utf-8"))
            except (TypeError, ValueError) as exc:
                raise SecretConfigurationError(
                    "La clé maître de chiffrement est invalide"
                ) from exc

        return self._fernet

    def encrypt_secret(self, plain_value: str) -> str:
        """Encrypt a plain-text secret."""
        fernet = self._get_fernet()
        return fernet.encrypt(plain_value.encode("utf-8")).decode("utf-8")

    def decrypt_secret(self, encrypted_value: str) -> str:
        """Decrypt a previously stored secret."""
        fernet = self._get_fernet()
        try:
            return fernet.decrypt(encrypted_value.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise SecretDecryptionError("Impossible de déchiffrer le secret stocké") from exc

    def build_secret_hint(self, plain_value: str) -> str | None:
        """Build a masked hint from a plain-text secret."""
        normalized_value = plain_value.strip()
        if not normalized_value:
            return None

        if len(normalized_value) <= 4:
            return "****"

        return f"****{normalized_value[-4:]}"

    def has_secret(self, encrypted_value: str | None) -> bool:
        """Return whether an encrypted secret is present."""
        return encrypted_value is not None and bool(encrypted_value.strip())
