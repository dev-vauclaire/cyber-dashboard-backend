"""Socle HTTP minimal standard library pour les validations externes."""

from __future__ import annotations

import json
import socket
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cyber_dashboard_api.integrations.common import IntegrationRequestError


DEFAULT_ACCEPT_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "cyber-dashboard-api/0.1",
}


class HttpJsonClient:
    """Client HTTP JSON minimal avec timeouts courts et erreurs normalisées."""

    def __init__(self, *, timeout_seconds: float) -> None:
        self._timeout_seconds = timeout_seconds

    def get_json(
        self,
        *,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[Any, int]:
        """Exécute un GET JSON et retourne le payload et le status HTTP."""
        final_url = url
        if params:
            final_url = f"{url}?{urlencode(params)}"

        request_headers = dict(DEFAULT_ACCEPT_HEADERS)
        if headers:
            request_headers.update(headers)

        request = Request(final_url, headers=request_headers, method="GET")

        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                payload = response.read().decode("utf-8")
                status_code = int(response.status)
        except HTTPError as exc:
            self._raise_http_error(exc)
        except URLError as exc:
            self._raise_url_error(exc)
        except TimeoutError as exc:
            raise IntegrationRequestError(
                "timeout",
                "The external service request timed out",
            ) from exc

        try:
            return json.loads(payload), status_code
        except json.JSONDecodeError as exc:
            raise IntegrationRequestError(
                "invalid_response",
                "The external service returned an invalid JSON response",
                status_code=status_code,
            ) from exc

    @staticmethod
    def _raise_http_error(exc: HTTPError) -> None:
        if exc.code in {401, 403}:
            raise IntegrationRequestError(
                "auth_rejected",
                "The external service rejected the provided credentials",
                status_code=exc.code,
            ) from exc
        if exc.code == 429:
            raise IntegrationRequestError(
                "rate_limit",
                "The external service rate limit has been reached",
                status_code=exc.code,
            ) from exc
        if exc.code >= 500:
            raise IntegrationRequestError(
                "service_unavailable",
                "The external service is temporarily unavailable",
                status_code=exc.code,
            ) from exc
        raise IntegrationRequestError(
            "http_error",
            "The external service returned an unexpected HTTP error",
            status_code=exc.code,
        ) from exc

    @staticmethod
    def _raise_url_error(exc: URLError) -> None:
        reason = exc.reason

        if isinstance(reason, socket.timeout):
            raise IntegrationRequestError(
                "timeout",
                "The external service request timed out",
            ) from exc
        if isinstance(reason, socket.gaierror):
            raise IntegrationRequestError(
                "dns_error",
                "The external service hostname could not be resolved",
            ) from exc
        if isinstance(reason, OSError):
            raise IntegrationRequestError(
                "network_error",
                "The external service request failed",
            ) from exc
        raise IntegrationRequestError(
            "network_error",
            "The external service request failed",
        ) from exc
