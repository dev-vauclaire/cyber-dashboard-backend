"""Client minimal pour interroger l'API Shodan."""

from __future__ import annotations

from cyber_dashboard_api.integrations.cti.clients.base import HttpJsonClient


class ShodanClient:
    """Expose les appels Shodan utilises par l'API."""

    def __init__(self, *, timeout_seconds: float) -> None:
        self._http_client = HttpJsonClient(timeout_seconds=timeout_seconds)

    def get_host_report(
        self,
        *,
        api_key: str,
        ip_address: str,
    ) -> tuple[object, int]:
        """Recupere les informations Shodan associees a une adresse IP."""
        return self._http_client.get_json(
            url=f"https://api.shodan.io/shodan/host/{ip_address}",
            params={
                "key": api_key
            },
        )

    def validate_api_key(self, *, api_key: str, test_ip: str) -> int:
        """Effectue un appel léger à Shodan."""
        _, status_code = self.get_host_report(
            api_key=api_key,
            ip_address=test_ip,
        )
        return status_code
