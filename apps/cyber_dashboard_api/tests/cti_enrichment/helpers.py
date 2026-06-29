"""Helpers partages pour les tests d'enrichissement CTI."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from cyber_dashboard_api.config import SecretSettings
from cyber_dashboard_api.integrations.common import IntegrationRequestError
from cyber_dashboard_api.services import SecretService


def build_valid_fernet_key() -> str:
    """Construit une cle Fernet valide pour les tests."""
    return base64.urlsafe_b64encode(b"4" * 32).decode("utf-8")


def build_secret_service() -> SecretService:
    """Construit le service de secrets utilise dans les tests d'enrichissement."""
    return SecretService(
        SecretSettings(
            secret_key_file=None,
            secret_key=build_valid_fernet_key(),
        )
    )


def fixed_now() -> datetime:
    """Horodatage stable pour les assertions."""
    return datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)


def build_cti_row(
    *,
    code: str = "abuseipdb",
    label: str = "AbuseIPDB",
    is_active: bool = True,
    is_key_required: bool = True,
    encrypted_api_key: str | None = None,
) -> dict[str, Any]:
    """Construit une ligne CTI representative."""
    return {
        "id": 1,
        "code": code,
        "label": label,
        "is_key_required": is_key_required,
        "encrypted_api_key": encrypted_api_key,
        "api_key_hint": "****1234" if encrypted_api_key else None,
        "is_active": is_active,
        "last_validation_status": "success" if is_active else "not_tested",
        "last_validation_at": fixed_now() if is_active else None,
        "last_validation_error": None,
        "created_at": fixed_now(),
        "updated_at": fixed_now(),
    }


def build_abuseipdb_payload() -> dict[str, Any]:
    """Construit un payload AbuseIPDB representative."""
    return {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 42,
            "countryCode": "US",
            "isp": "Google LLC",
            "totalReports": 4,
            "lastReportedAt": "2026-06-02T14:44:09+00:00",
            "reports": [
                {"categories": [15, 18]},
                {"categories": [18]},
                {"categories": [4, 15]},
                {"categories": [18]},
            ],
        }
    }


def build_virustotal_payload() -> dict[str, Any]:
    """Construit un payload VirusTotal representative."""
    return {
        "data": {
            "id": "8.8.8.8",
            "attributes": {
                "reputation": -12,
                "country": "US",
                "as_owner": "Google LLC",
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 12,
                    "undetected": 54,
                    "timeout": 0,
                },
            },
        }
    }


def build_ipdata_payload() -> dict[str, Any]:
    """Construit un payload IPData representative."""
    return {
        "ip": "8.8.8.8",
        "country_name": "United States",
        "asn": {
            "name": "Google LLC",
        },
        "threat": {
            "is_threat": True,
        },
    }


def build_ipinfo_payload() -> dict[str, Any]:
    """Construit un payload IPinfo representative."""
    return {
        "ip": "8.8.8.8",
        "asn": "AS15169",
        "as_name": "Google LLC",
        "as_domain": "google.com",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America",
    }


def build_greynoise_payload() -> dict[str, Any]:
    """Construit un payload GreyNoise representative."""
    return {
        "ip": "71.6.135.131",
        "noise": True,
        "riot": False,
        "classification": "benign",
        "name": "Shodan.io",
        "link": "https://viz.greynoise.io/ip/71.6.135.131",
        "last_seen": "2026-06-10",
        "message": "Success",
    }


def build_shodan_payload() -> dict[str, Any]:
    """Construit un payload Shodan representative."""
    return {
        "ip_str": "8.8.8.8",
        "country_name": "United States",
        "hostnames": ["dns.google"],
        "org": "Google",
        "asn": "AS15169",
        "last_update": "2026-06-10T08:49:35.190817",
        "vulns": {
            "CVE-2024-0001": {},
            "CVE-2024-0002": {},
        },
        "data": [
            {
                "_shodan": {"module": "dns-udp"},
                "port": 53,
                "transport": "udp",
                "timestamp": "2026-06-08T08:49:35.190817",
                "opts": {
                    "vulns": ["CVE-2023-9999"],
                },
            },
            {
                "_shodan": {"module": "https"},
                "port": 443,
                "transport": "tcp",
                "timestamp": "2026-06-09T08:49:35.190817",
                "vulns": ["CVE-2024-0001"],
                "ssl": {"enabled": True},
            },
            {
                "_shodan": {"module": "http"},
                "port": 80,
                "transport": "tcp",
                "timestamp": "2026-06-07T08:49:35.190817",
            },
        ],
    }


def build_rdap_payload() -> dict[str, Any]:
    """Construit un payload RDAP representative."""
    return {
        "handle": "8.8.8.8",
        "name": "GOGL",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        [
                            "adr",
                            {
                                "label": "Google LLC\n1600 Amphitheatre Pkwy\nUnited States"
                            },
                            "text",
                            "",
                        ]
                    ],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [
                                [
                                    "email",
                                    {},
                                    "text",
                                    "abuse@google.example",
                                ]
                            ],
                        ],
                    }
                ],
            }
        ],
    }


class FakeCtiConfigRepository:
    """Repository CTI minimal en memoire pour les tests d'enrichissement."""

    def __init__(self, row: dict[str, Any] | None) -> None:
        self.row = None if row is None else deepcopy(row)

    def get_by_code(self, code: str) -> dict[str, Any] | None:
        if self.row is None or self.row["code"] != code:
            return None
        return deepcopy(self.row)


class FakeAbuseIpdbClient:
    """Client AbuseIPDB fake configurable."""

    def __init__(
        self,
        *,
        payload: object | None = None,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
        max_age_in_days: int,
        verbose: bool,
    ) -> tuple[object, int]:
        self.calls.append(
            {
                "api_key": api_key,
                "ip_address": ip_address,
                "max_age_in_days": max_age_in_days,
                "verbose": verbose,
            }
        )
        if self.error is not None:
            raise self.error
        return deepcopy(self.payload), self.status_code


class FakeVirusTotalClient:
    """Client VirusTotal fake configurable."""

    def __init__(
        self,
        *,
        payload: object | None = None,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
    ) -> tuple[object, int]:
        self.calls.append(
            {
                "api_key": api_key,
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        return deepcopy(self.payload), self.status_code


class FakeIpDataClient:
    """Client IPData fake configurable."""

    def __init__(
        self,
        *,
        payload: object | None = None,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
    ) -> tuple[object, int]:
        self.calls.append(
            {
                "api_key": api_key,
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        return deepcopy(self.payload), self.status_code


class FakeIpinfoClient:
    """Client IPinfo fake configurable."""

    def __init__(
        self,
        *,
        payload: object | None = None,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
    ) -> tuple[object, int]:
        self.calls.append(
            {
                "api_key": api_key,
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        return deepcopy(self.payload), self.status_code


class FakeGreyNoiseClient:
    """Client GreyNoise fake configurable."""

    def __init__(
        self,
        *,
        payload: object | None = None,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_ip_report(
        self,
        *,
        api_key: str,
        ip_address: str,
    ) -> tuple[object, int]:
        self.calls.append(
            {
                "api_key": api_key,
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        return deepcopy(self.payload), self.status_code


class FakeRdapClient:
    """Client RDAP fake configurable."""

    def __init__(
        self,
        *,
        payload: object | None = None,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_ip_report(
        self,
        *,
        ip_address: str,
    ) -> tuple[object, int]:
        self.calls.append(
            {
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        return deepcopy(self.payload), self.status_code


class FakeShodanClient:
    """Client Shodan fake configurable."""

    def __init__(
        self,
        *,
        payload: object | None = None,
        status_code: int = 200,
        error: IntegrationRequestError | None = None,
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_host_report(
        self,
        *,
        api_key: str,
        ip_address: str,
        minify: bool = False,
    ) -> tuple[object, int]:
        self.calls.append(
            {
                "api_key": api_key,
                "ip_address": ip_address,
                "minify": minify,
            }
        )
        if self.error is not None:
            raise self.error
        return deepcopy(self.payload), self.status_code


class FakeCtiEnrichmentService:
    """Service fake pour les tests de routes CTI enrichment."""

    def __init__(
        self,
        *,
        result: dict[str, Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def enrich_with_abuseipdb(
        self,
        *,
        ip_address: str,
        max_age_in_days: int,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "ip_address": ip_address,
                "max_age_in_days": max_age_in_days,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("No fake result configured")
        return deepcopy(self.result)

    def enrich_with_virustotal(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("No fake result configured")
        return deepcopy(self.result)

    def enrich_with_ipdata(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("No fake result configured")
        return deepcopy(self.result)

    def enrich_with_ipinfo(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("No fake result configured")
        return deepcopy(self.result)

    def enrich_with_greynoise(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("No fake result configured")
        return deepcopy(self.result)

    def enrich_with_rdap(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("No fake result configured")
        return deepcopy(self.result)

    def enrich_with_shodan(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "ip_address": ip_address,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("No fake result configured")
        return deepcopy(self.result)
