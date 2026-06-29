"""Client minimal pour interroger l'API IPinfo Lite."""

from __future__ import annotations

from cyber_dashboard_api.integrations.cti.clients.base import HttpJsonClient


class IpinfoClient:
    """Expose les appels IPinfo utilises par l'API."""

    def __init__(self, *, timeout_seconds: float) -> None:
        self._http_client = HttpJsonClient(timeout_seconds=timeout_seconds)

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
    ) -> tuple[object, int]:
        """Recupere le rapport IPinfo Lite associe a une adresse IP."""
        return self._http_client.get_json(
            url=f"https://api.ipinfo.io/lite/{ip_address}",
            params={"token": api_key},
        )

    def validate_api_key(self, *, api_key: str, test_ip: str) -> int:
        """Effectue un appel leger a IPinfo Lite."""
        _, status_code = self.get_ip_report(
            api_key=api_key,
            ip_address=test_ip,
        )
        return status_code
