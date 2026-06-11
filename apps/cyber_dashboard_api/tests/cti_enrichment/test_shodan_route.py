"""Tests de la route GET /api/cti-enrichment/shodan."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address

from cyber_dashboard_api.api.routes.cti_enrichment import get_shodan_enrichment

from tests.cti_enrichment.helpers import FakeCtiEnrichmentService


class ShodanEnrichmentRouteTestCase(unittest.TestCase):
    """Couvre la route Shodan d'enrichissement CTI."""

    def test_route_returns_typed_response(self) -> None:
        service = FakeCtiEnrichmentService(
            result={
                "ip_address": "8.8.8.8",
                "organization": "Google",
                "asn": "AS15169",
                "country_name": "United States",
                "hostnames": ["dns.google"],
                "exposed_ports": ["53/udp", "443/tcp"],
                "services": ["DNS", "HTTPS"],
                "known_vulnerabilities_count": 2,
                "vulnerabilities": ["CVE-2024-0001", "CVE-2024-0002"],
                "last_observed_at": "2026-06-10T08:49:35.190817+00:00",
            }
        )

        response = get_shodan_enrichment(
            ip_address=IPv4Address("8.8.8.8"),
            cti_enrichment_service=service,
        )

        payload = response.model_dump(mode="json")
        self.assertEqual(payload["ip_address"], "8.8.8.8")
        self.assertEqual(payload["organization"], "Google")
        self.assertEqual(payload["services"], ["DNS", "HTTPS"])
        self.assertEqual(service.calls[0]["ip_address"], "8.8.8.8")
