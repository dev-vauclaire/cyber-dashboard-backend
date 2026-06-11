"""Tests de la route GET /api/cti-enrichment/greynoise."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address

from cyber_dashboard_api.api.routes.cti_enrichment import get_greynoise_enrichment

from tests.cti_enrichment.helpers import FakeCtiEnrichmentService


class GreyNoiseEnrichmentRouteTestCase(unittest.TestCase):
    """Couvre la route GreyNoise d'enrichissement CTI."""

    def test_route_returns_typed_response(self) -> None:
        service = FakeCtiEnrichmentService(
            result={
                "ip_address": "71.6.135.131",
                "classification": "benign",
                "name": "Shodan.io",
                "link": "https://viz.greynoise.io/ip/71.6.135.131",
                "last_seen": "2026-06-10",
            }
        )

        response = get_greynoise_enrichment(
            ip_address=IPv4Address("71.6.135.131"),
            cti_enrichment_service=service,
        )

        payload = response.model_dump(mode="json")
        self.assertEqual(payload["ip_address"], "71.6.135.131")
        self.assertEqual(payload["classification"], "benign")
        self.assertEqual(payload["name"], "Shodan.io")
        self.assertEqual(payload["link"], "https://viz.greynoise.io/ip/71.6.135.131")
        self.assertEqual(payload["last_seen"], "2026-06-10")
        self.assertEqual(service.calls[0]["ip_address"], "71.6.135.131")
