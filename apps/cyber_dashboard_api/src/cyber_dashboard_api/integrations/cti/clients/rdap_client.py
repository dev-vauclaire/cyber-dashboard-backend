"""Client minimal pour interroger le service RDAP public."""

from __future__ import annotations

from cyber_dashboard_api.integrations.cti.clients.base import HttpJsonClient


class RdapClient:
    """Expose les appels RDAP utilises par l'API."""

    def __init__(self, *, timeout_seconds: float) -> None:
        self._http_client = HttpJsonClient(timeout_seconds=timeout_seconds)

    def get_ip_report(self, *, ip_address: str) -> tuple[object, int]:
        """Recupere le rapport RDAP associe a une adresse IP."""
        return self._http_client.get_json(
            url=f"https://rdap.org/ip/{ip_address}",
        )
