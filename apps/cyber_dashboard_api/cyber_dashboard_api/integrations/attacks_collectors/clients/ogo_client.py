"""Client minimal pour valider une configuration OGO via la nouvelle API."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from cyber_dashboard_api.integrations.attacks_collectors.clients.base import (
    HttpJsonClient,
)
from cyber_dashboard_api.integrations.common import IntegrationRequestError

REQUIRED_JOURNAL_PRIVILEGES = frozenset({"export_logs"})


@dataclass(frozen=True)
class OgoOrganizationAccess:
    """Représente les droits détectés sur une organisation OGO."""

    organization_code: str
    organization_name: str | None
    role: str | None
    privileges: tuple[str, ...]
    has_journal_access: bool


@dataclass(frozen=True)
class OgoCredentialsValidationResult:
    """Résultat de validation des credentials OGO."""

    status_code: int
    authenticated: bool
    has_journal_access: bool
    organizations: tuple[OgoOrganizationAccess, ...]


class OgoClient:
    """Valide les credentials OGO et les privilèges via /v2/organizations."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._http_client = HttpJsonClient(timeout_seconds=timeout_seconds)

    def validate_credentials(
        self,
        *,
        email: str,
        api_key: str,
    ) -> OgoCredentialsValidationResult:
        """Valide l'accès OGO et vérifie les privilèges de lecture/export des logs.

        Cette méthode ne nécessite pas encore organization_code ni site_domain_name.
        Elle vérifie uniquement que le compte a accès à au moins une organisation
        avec le privilège requis pour exploiter les journaux.

        Args:
            email: Email du compte OGO.
            api_key: Clé API OGO.

        Returns:
            Résultat typé contenant le status HTTP, l'état d'authentification
            et les organisations où le privilège journal est présent.
        """
        endpoint = "/v2/organizations"

        payload, status_code = self._http_client.get_json(
            url=f"{self._base_url}{endpoint}",
            headers=self._build_auth_headers(
                email=email,
                api_key=api_key,
                endpoint=endpoint,
            ),
        )

        if status_code < 200 or status_code >= 300:
            return OgoCredentialsValidationResult(
                status_code=status_code,
                authenticated=False,
                has_journal_access=False,
                organizations=(),
            )

        organizations = self._extract_organization_accesses(payload)

        return OgoCredentialsValidationResult(
            status_code=status_code,
            authenticated=True,
            has_journal_access=any(
                organization.has_journal_access for organization in organizations
            ),
            organizations=tuple(organizations),
        )

    def _build_auth_headers(
        self,
        *,
        email: str,
        api_key: str,
        endpoint: str,
    ) -> dict[str, str]:
        """Construit le header x-ogo-auth attendu par la nouvelle API OGO."""
        raw_token = f"{endpoint}-{api_key}"
        token = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        return {
            "x-ogo-auth": f"{email};{token}",
            "Accept": "application/json",
        }

    def _extract_organization_accesses(
        self,
        payload: Any,
    ) -> list[OgoOrganizationAccess]:
        """Extrait les droits par organisation depuis la réponse paginée OGO."""
        if not isinstance(payload, dict):
            raise IntegrationRequestError(
                "invalid_response",
                "OGO a renvoyé une charge utile de réponse inattendue",
            )

        content = payload.get("content")
        if not isinstance(content, list):
            raise IntegrationRequestError(
                "invalid_response",
                "OGO a renvoyé une réponse sans liste 'content' valide",
            )

        organizations: list[OgoOrganizationAccess] = []

        for item in content:
            if not isinstance(item, dict):
                raise IntegrationRequestError(
                    "invalid_response",
                    "OGO a renvoyé une entrée d'organisation invalide",
                )

            organization = item.get("organization") or {}

            organization_code = organization.get("code")
            if not organization_code:
                continue

            raw_privileges = item.get("privileges")
            if raw_privileges is None:
                raw_privileges = []
            if not isinstance(raw_privileges, list):
                raise IntegrationRequestError(
                    "invalid_response",
                    "OGO a renvoyé une liste de privilèges invalide",
                )

            privileges = tuple(
                privilege for privilege in raw_privileges if isinstance(privilege, str)
            )
            normalized_privileges = {
                _normalize_privilege_name(privilege) for privilege in privileges
            }

            has_journal_access = REQUIRED_JOURNAL_PRIVILEGES.issubset(
                normalized_privileges
            )

            organizations.append(
                OgoOrganizationAccess(
                    organization_code=organization_code,
                    organization_name=organization.get("name"),
                    role=item.get("role"),
                    privileges=privileges,
                    has_journal_access=has_journal_access,
                )
            )

        return organizations


def _normalize_privilege_name(value: str) -> str:
    """Normalise les privileges pour accepter les variantes de format."""
    return value.strip().lower().replace(" ", "_")
