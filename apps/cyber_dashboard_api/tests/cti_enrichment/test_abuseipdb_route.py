"""Tests de la route GET /api/cti-enrichment/abuseipdb."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address

from cyber_dashboard_api.api.routes.cti_enrichment import get_abuseipdb_enrichment

from tests.cti_enrichment.helpers import FakeCtiEnrichmentService


class AbuseIpdbEnrichmentRouteTestCase(unittest.TestCase):
    """Couvre la route AbuseIPDB d'enrichissement CTI."""

    def test_route_returns_typed_response(self) -> None:
        service = FakeCtiEnrichmentService(
            result={
                "ip_address": "8.8.8.8",
                "abuse_confidence_score": 42,
                "country_code": "US",
                "isp": "Google LLC",
                "last_reported_at": "2026-06-02T14:44:09+00:00",
                "total_reports": 4,
                "category_percentages": [
                    {"category_code": 4, "percentage": 25.0},
                    {"category_code": 15, "percentage": 50.0},
                ],
            }
        )

        response = get_abuseipdb_enrichment(
            ip_address=IPv4Address("8.8.8.8"),
            max_age_in_days=30,
            cti_enrichment_service=service,
        )

        payload = response.model_dump(mode="json")
        self.assertEqual(payload["ip_address"], "8.8.8.8")
        self.assertEqual(payload["abuse_confidence_score"], 42)
        self.assertEqual(service.calls[0]["ip_address"], "8.8.8.8")
        self.assertEqual(service.calls[0]["max_age_in_days"], 30)
