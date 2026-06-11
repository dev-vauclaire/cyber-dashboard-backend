"""Tests de la route GET /api/cti-enrichment/ipdata."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address

from cyber_dashboard_api.api.routes.cti_enrichment import get_ipdata_enrichment

from tests.cti_enrichment.helpers import FakeCtiEnrichmentService


class IpDataEnrichmentRouteTestCase(unittest.TestCase):
    """Couvre la route IPData d'enrichissement CTI."""

    def test_route_returns_typed_response(self) -> None:
        service = FakeCtiEnrichmentService(
            result={
                "ip_address": "8.8.8.8",
                "country_name": "United States",
                "asn_name": "Google LLC",
                "is_threat": True,
            }
        )

        response = get_ipdata_enrichment(
            ip_address=IPv4Address("8.8.8.8"),
            cti_enrichment_service=service,
        )

        payload = response.model_dump(mode="json")
        self.assertEqual(payload["ip_address"], "8.8.8.8")
        self.assertEqual(payload["country_name"], "United States")
        self.assertEqual(payload["asn_name"], "Google LLC")
        self.assertTrue(payload["is_threat"])
        self.assertEqual(service.calls[0]["ip_address"], "8.8.8.8")
