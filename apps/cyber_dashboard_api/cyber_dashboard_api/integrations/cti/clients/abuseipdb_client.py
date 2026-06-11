"""Client minimal pour valider une clé API AbuseIPDB."""

from __future__ import annotations

from cyber_dashboard_api.integrations.cti.clients.base import HttpJsonClient


class AbuseIpdbClient:
    """Valide l'accès AbuseIPDB via un lookup léger."""

    def __init__(self, *, timeout_seconds: float) -> None:
        self._http_client = HttpJsonClient(timeout_seconds=timeout_seconds)

    def validate_api_key(self, *, api_key: str, test_ip: str) -> int:
        """Effectue un appel léger à AbuseIPDB."""
        _, status_code = self.get_ip_report(
            api_key=api_key,
            ip_address=test_ip,
            max_age_in_days=30,
            verbose=False,
        )
        return status_code

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
        max_age_in_days: int,
        verbose: bool,
    ) -> tuple[object, int]:
        """Recupere le rapport AbuseIPDB d'une adresse IP."""
        return self._http_client.get_json(
            url="https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key},
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_in_days,
                "verbose": "true" if verbose else "false",
            },
        )
