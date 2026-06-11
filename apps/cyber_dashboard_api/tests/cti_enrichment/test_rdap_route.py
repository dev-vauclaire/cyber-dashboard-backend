"""Tests de la route GET /api/cti-enrichment/rdap."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address

from cyber_dashboard_api.api.routes.cti_enrichment import get_rdap_enrichment

from tests.cti_enrichment.helpers import FakeCtiEnrichmentService


class RdapEnrichmentRouteTestCase(unittest.TestCase):
    """Couvre la route RDAP d'enrichissement CTI."""

    def test_route_returns_typed_response(self) -> None:
        service = FakeCtiEnrichmentService(
            result={
                "ip_address": "8.8.8.8",
                "name": "GOGL",
                "country": "United States",
                "abuse_contact_email": "abuse@google.example",
                "start_address": "8.8.8.0",
                "end_address": "8.8.8.255",
            }
        )

        response = get_rdap_enrichment(
            ip_address=IPv4Address("8.8.8.8"),
            cti_enrichment_service=service,
        )

        payload = response.model_dump(mode="json")
        self.assertEqual(payload["ip_address"], "8.8.8.8")
        self.assertEqual(payload["name"], "GOGL")
        self.assertEqual(payload["country"], "United States")
        self.assertEqual(payload["abuse_contact_email"], "abuse@google.example")
        self.assertEqual(service.calls[0]["ip_address"], "8.8.8.8")
