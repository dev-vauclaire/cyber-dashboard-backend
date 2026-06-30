"""Tests de la route GET /api/cti-enrichment/ipinfo."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address

from cyber_dashboard_api.api.routes.cti_enrichment import get_ipinfo_enrichment

from tests.cti_enrichment.helpers import FakeCtiEnrichmentService


class IpinfoEnrichmentRouteTestCase(unittest.TestCase):
    """Couvre la route IPinfo d'enrichissement CTI."""

    def test_route_returns_typed_response(self) -> None:
        service = FakeCtiEnrichmentService(
            result={
                "ip_address": "8.8.8.8",
                "asn": "AS15169",
                "as_name": "Google LLC",
                "as_domain": "google.com",
                "country_code": "US",
                "country": "United States",
                "continent_code": "NA",
                "continent": "North America",
            }
        )

        response = get_ipinfo_enrichment(
            ip_address=IPv4Address("8.8.8.8"),
            cti_enrichment_service=service,
        )

        payload = response.model_dump(mode="json")
        self.assertEqual(payload["ip_address"], "8.8.8.8")
        self.assertEqual(payload["asn"], "AS15169")
        self.assertEqual(payload["as_name"], "Google LLC")
        self.assertEqual(payload["as_domain"], "google.com")
        self.assertEqual(payload["country_code"], "US")
        self.assertEqual(payload["country"], "United States")
        self.assertEqual(payload["continent_code"], "NA")
        self.assertEqual(payload["continent"], "North America")
        self.assertEqual(service.calls[0]["ip_address"], "8.8.8.8")
