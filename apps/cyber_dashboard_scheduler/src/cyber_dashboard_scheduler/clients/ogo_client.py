"""Client HTTP minimal pour l'API OGO V2."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Any

import requests

from cyber_dashboard_scheduler.utils import format_utc_datetime_for_api

from .serenicity_base_client import ApiClientError


@dataclass(frozen=True, slots=True)
class OgoJournalFetchResult:
    """Resultat agrege d'une lecture paginee du journal OGO."""

    items: list[dict[str, Any]]
    pages_read: int
    total_count: int


class OgoApiClient:
    """Expose les endpoints OGO V2 utilises par le scheduler."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Le timeout HTTP OGO doit etre strictement positif")

        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    def list_organizations(
        self,
        *,
        email: str,
        api_key: str,
        lang: str = "fr",
    ) -> list[dict[str, Any]]:
        """Retourne toutes les organisations visibles via OGO V2."""
        path = "/v2/organizations"
        page_number = 0
        organizations: list[dict[str, Any]] = []

        while True:
            payload = self._request_json(
                path=path,
                email=email,
                api_key=api_key,
                lang=lang,
                params={"page": page_number, "size": 100},
            )
            parsed_page = self._parse_page_payload(
                payload,
                endpoint_label=path,
                item_label="organizations",
            )
            organizations.extend(parsed_page["items"])
            if page_number >= parsed_page["last_page_number"]:
                break
            page_number += 1

        return organizations

    def list_sites(
        self,
        *,
        email: str,
        api_key: str,
        organization_code: str,
        lang: str = "fr",
    ) -> list[dict[str, Any]]:
        """Retourne tous les domaines visibles pour une organisation OGO."""
        path = f"/v2/organizations/{organization_code}/sites"
        page_number = 0
        sites: list[dict[str, Any]] = []

        while True:
            payload = self._request_json(
                path=path,
                email=email,
                api_key=api_key,
                lang=lang,
                params={"page": page_number, "size": 100},
            )
            parsed_page = self._parse_page_payload(
                payload,
                endpoint_label=path,
                item_label="sites",
            )
            sites.extend(parsed_page["items"])
            if page_number >= parsed_page["last_page_number"]:
                break
            page_number += 1

        return sites

    def list_journal_events(
        self,
        *,
        email: str,
        api_key: str,
        organization_code: str,
        after: datetime,
        before: datetime,
        sites: list[str],
        lang: str = "fr",
    ) -> OgoJournalFetchResult:
        """Retourne tous les evenements SECURITY du journal OGO pour un ou plusieurs sites."""
        path = f"/v2/organizations/{organization_code}/journal"
        page_number = 0
        pages_read = 0
        total_count = 0
        items: list[dict[str, Any]] = []

        while True:
            payload = self._request_json(
                path=path,
                email=email,
                api_key=api_key,
                lang=lang,
                params={
                    "after": format_utc_datetime_for_api(after),
                    "before": format_utc_datetime_for_api(before),
                    "type": ["SECURITY"],
                    "sites": sites,
                    "page": page_number,
                    "size": 100,
                    "sort": ["date,asc"],
                },
            )
            parsed_page = self._parse_journal_page_payload(payload, endpoint_label=path)
            pages_read += 1
            total_count = parsed_page["total_count"]
            items.extend(parsed_page["items"])
            if page_number >= parsed_page["last_page_number"]:
                break
            page_number += 1

        return OgoJournalFetchResult(
            items=items,
            pages_read=pages_read,
            total_count=total_count,
        )

    def _request_json(
        self,
        *,
        path: str,
        email: str,
        api_key: str,
        lang: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Exécute un GET signé avec le header `x-ogo-auth`."""
        url = f"{self._base_url}{path}"
        headers = {
            "Accept": "application/json",
            "lang": lang,
            "x-ogo-auth": _build_ogo_v2_auth_header(
                path=path,
                email=email,
                api_key=api_key,
            ),
        }
        try:
            response = self._session.get(
                url,
                headers=headers,
                params=params,
                timeout=self._timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ApiClientError(f"Echec de l'appel API OGO {url}: {exc}") from exc

        try:
            return response.json()
        except ValueError as exc:
            raise ApiClientError(
                f"Reponse JSON invalide pour l'appel API OGO {url}"
            ) from exc

    @staticmethod
    def _parse_page_payload(
        payload: Any,
        *,
        endpoint_label: str,
        item_label: str,
    ) -> dict[str, Any]:
        """Valide une reponse paginee standard d'OGO V2."""
        if not isinstance(payload, dict):
            raise ApiClientError(
                f"Format inattendu pour la reponse OGO {endpoint_label}"
            )

        items = payload.get("content")
        if not isinstance(items, list) or not all(
            isinstance(item, dict) for item in items
        ):
            raise ApiClientError(
                f"Format inattendu pour le champ content des {item_label} OGO"
            )

        total_pages = _parse_non_negative_int(
            payload.get("totalPages", 1), "totalPages"
        )
        if not items and total_pages == 0:
            return {"items": [], "last_page_number": 0}
        if total_pages <= 0:
            raise ApiClientError(
                f"Pagination inattendue pour la reponse OGO {endpoint_label}"
            )

        return {
            "items": items,
            "last_page_number": max(total_pages - 1, 0),
        }

    @staticmethod
    def _parse_journal_page_payload(
        payload: Any, *, endpoint_label: str
    ) -> dict[str, Any]:
        """Valide une reponse paginee du journal OGO."""
        if not isinstance(payload, dict):
            raise ApiClientError(
                f"Format inattendu pour la reponse OGO {endpoint_label}"
            )

        items = payload.get("content")
        if not isinstance(items, list) or not all(
            isinstance(item, dict) for item in items
        ):
            raise ApiClientError(
                f"Format inattendu pour le champ content du journal OGO {endpoint_label}"
            )

        total_pages = _parse_non_negative_int(
            payload.get("totalPages", 1), "totalPages"
        )
        total_count = _parse_non_negative_int(
            payload.get("totalElements", 0), "totalElements"
        )

        if not items and total_pages == 0:
            return {
                "items": [],
                "last_page_number": 0,
                "total_count": 0,
            }

        if total_pages <= 0:
            raise ApiClientError(
                f"Pagination inattendue pour la reponse OGO {endpoint_label}"
            )

        return {
            "items": items,
            "last_page_number": max(total_pages - 1, 0),
            "total_count": total_count,
        }


def _build_ogo_v2_auth_header(*, path: str, email: str, api_key: str) -> str:
    """Construit la valeur du header `x-ogo-auth` pour OGO V2."""
    normalized_email = email.strip()
    normalized_api_key = api_key.strip()
    raw = f"{path}-{normalized_api_key}"
    token = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"{normalized_email};{token}"


def _parse_non_negative_int(value: Any, field_name: str) -> int:
    """Valide un entier positif ou nul renvoye par OGO."""
    try:
        parsed_value = int(value)
    except (TypeError, ValueError) as exc:
        raise ApiClientError(
            f"Valeur entiere invalide dans la reponse OGO : {field_name}"
        ) from exc

    if parsed_value < 0:
        raise ApiClientError(
            f"Valeur entiere positive ou nulle attendue dans la reponse OGO : {field_name}"
        )
    return parsed_value
