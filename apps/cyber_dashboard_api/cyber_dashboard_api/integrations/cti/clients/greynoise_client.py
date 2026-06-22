"""Client minimal pour interroger l'API GreyNoise."""

from __future__ import annotations

from cyber_dashboard_api.integrations.cti.clients.base import HttpJsonClient


class GreyNoiseClient:
    """Expose les appels GreyNoise utilises par l'API."""

    def __init__(self, *, timeout_seconds: float) -> None:
        self._http_client = HttpJsonClient(timeout_seconds=timeout_seconds)

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
    ) -> tuple[object, int]:
        """Recupere le rapport GreyNoise associe a une adresse IP."""
        return self._http_client.get_json(
            url=f"https://api.greynoise.io/v3/community/{ip_address}",
            headers={"key": api_key},
        )

    def validate_api_key(self, *, api_key: str) -> int:
        """Valide une clé via l'endpoint GreyNoise dédié à l'accès API."""
        _, status_code = self._http_client.get_json(
            url="https://api.greynoise.io/ping",
            headers={"key": api_key},
        )
        return status_code
