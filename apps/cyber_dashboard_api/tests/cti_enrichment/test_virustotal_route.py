"""Tests de la route GET /api/cti-enrichment/virustotal."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address

from cyber_dashboard_api.api.routes.cti_enrichment import get_virustotal_enrichment

from tests.cti_enrichment.helpers import FakeCtiEnrichmentService


class VirusTotalEnrichmentRouteTestCase(unittest.TestCase):
    """Couvre la route VirusTotal d'enrichissement CTI."""

    def test_route_returns_typed_response(self) -> None:
        service = FakeCtiEnrichmentService(
            result={
                "ip_address": "8.8.8.8",
                "reputation": -12,
                "country_code": "US",
                "as_owner": "Google LLC",
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 12,
                    "undetected": 54,
                    "timeout": 0,
                },
            }
        )

        response = get_virustotal_enrichment(
            ip_address=IPv4Address("8.8.8.8"),
            cti_enrichment_service=service,
        )

        payload = response.model_dump(mode="json")
        self.assertEqual(payload["ip_address"], "8.8.8.8")
        self.assertEqual(payload["reputation"], -12)
        self.assertEqual(payload["last_analysis_stats"]["malicious"], 3)
        self.assertEqual(service.calls[0]["ip_address"], "8.8.8.8")
