"""Client minimal pour valider une configuration Serenicity."""

from __future__ import annotations

from cyber_dashboard_api.integrations.attacks_collectors.clients.base import (
    HttpJsonClient,
)


class SerenicityClient:
    """Valide les credentials Serenicity via une lecture légère."""

    def __init__(self, *, base_url: str, timeout_seconds: float) -> None:
        self._base_url = base_url.rstrip("/")
        self._http_client = HttpJsonClient(timeout_seconds=timeout_seconds)

    def validate_credentials(self, *, api_key: str) -> int:
        """Effectue un appel léger à l'API Serenicity."""
        _, status_code = self._http_client.get_json(
            url=f"{self._base_url}/sensors",
            headers={"Authorization": f"Api-Key {api_key}"},
        )
        return status_code
