"""Types et exceptions communs aux integrations externes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Résultat normalisé d'une validation externe."""

    success: bool
    message: str | None = None
    provider_status_code: int | None = None

    @classmethod
    def ok(cls, *, provider_status_code: int | None = 200) -> "ValidationResult":
        """Construit un résultat de validation réussi."""
        return cls(
            success=True, message=None, provider_status_code=provider_status_code
        )

    @classmethod
    def fail(
        cls,
        message: str,
        *,
        provider_status_code: int | None = None,
    ) -> "ValidationResult":
        """Construit un résultat de validation en échec."""
        return cls(
            success=False,
            message=message,
            provider_status_code=provider_status_code,
        )


class IntegrationRequestError(RuntimeError):
    """Erreur réseau ou protocolaire normalisée pour les validateurs."""

    def __init__(
        self,
        kind: str,
        message: str,
        *,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code
