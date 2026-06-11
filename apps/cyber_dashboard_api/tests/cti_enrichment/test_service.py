"""Tests unitaires du service d'enrichissement CTI."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from cyber_dashboard_api.api.errors import BadRequestError, NotFoundError, ServiceUnavailableError
from cyber_dashboard_api.integrations.common import IntegrationRequestError
from cyber_dashboard_api.services import CtiEnrichmentService

from tests.cti_enrichment.helpers import (
    FakeAbuseIpdbClient,
    FakeCtiConfigRepository,
    FakeGreyNoiseClient,
    FakeIpDataClient,
    FakeRdapClient,
    FakeShodanClient,
    FakeVirusTotalClient,
    build_abuseipdb_payload,
    build_cti_row,
    build_greynoise_payload,
    build_ipdata_payload,
    build_rdap_payload,
    build_shodan_payload,
    build_secret_service,
    build_virustotal_payload,
)


class CtiEnrichmentServiceTestCase(unittest.TestCase):
    """Couvre les enrichissements CTI exposes par le service."""

    def setUp(self) -> None:
        self.secret_service = build_secret_service()
        encrypted_api_key = self.secret_service.encrypt_secret("abuseipdb-api-key")
        self.repository = FakeCtiConfigRepository(
            build_cti_row(encrypted_api_key=encrypted_api_key)
        )
        self.abuseipdb_client = FakeAbuseIpdbClient(payload=build_abuseipdb_payload())
        self.greynoise_client = FakeGreyNoiseClient(payload=build_greynoise_payload())
        self.ipdata_client = FakeIpDataClient(payload=build_ipdata_payload())
        self.rdap_client = FakeRdapClient(payload=build_rdap_payload())
        self.shodan_client = FakeShodanClient(payload=build_shodan_payload())
        self.virustotal_client = FakeVirusTotalClient(payload=build_virustotal_payload())
        self.service = CtiEnrichmentService(
            self.repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
            self.shodan_client,
        )

    def test_enrich_with_abuseipdb_returns_expected_projection(self) -> None:
        result = self.service.enrich_with_abuseipdb(
            ip_address="8.8.8.8",
            max_age_in_days=45,
        )

        self.assertEqual(result["ip_address"], "8.8.8.8")
        self.assertEqual(result["abuse_confidence_score"], 42)
        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["isp"], "Google LLC")
        self.assertEqual(result["total_reports"], 4)
        self.assertEqual(
            result["category_percentages"],
            [
                {"category_code": 4, "percentage": 25.0},
                {"category_code": 15, "percentage": 50.0},
                {"category_code": 18, "percentage": 75.0},
            ],
        )
        self.assertEqual(self.abuseipdb_client.calls[0]["max_age_in_days"], 45)
        self.assertTrue(self.abuseipdb_client.calls[0]["verbose"])

    def test_enrich_with_abuseipdb_defaults_missing_fields(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("abuseipdb-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="abuseipdb",
                label="AbuseIPDB",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeAbuseIpdbClient(payload={})
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        result = service.enrich_with_abuseipdb(
            ip_address="8.8.8.8",
            max_age_in_days=30,
        )

        self.assertEqual(
            result,
            {
                "ip_address": "8.8.8.8",
                "abuse_confidence_score": 0,
                "country_code": None,
                "isp": None,
                "last_reported_at": None,
                "total_reports": 0,
                "category_percentages": [],
            },
        )

    def test_enrich_with_ipdata_returns_expected_projection(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("ipdata-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="ipdata",
                label="IPData",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeIpDataClient(payload=build_ipdata_payload())
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        result = service.enrich_with_ipdata(ip_address="8.8.8.8")

        self.assertEqual(result["ip_address"], "8.8.8.8")
        self.assertEqual(result["country_name"], "United States")
        self.assertEqual(result["asn_name"], "Google LLC")
        self.assertTrue(result["is_threat"])
        self.assertEqual(client.calls[0]["ip_address"], "8.8.8.8")

    def test_enrich_with_greynoise_returns_expected_projection(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("greynoise-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="greynoise",
                label="GreyNoise",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeGreyNoiseClient(payload=build_greynoise_payload())
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            client,
            self.rdap_client,
            self.virustotal_client,
        )

        result = service.enrich_with_greynoise(ip_address="71.6.135.131")

        self.assertEqual(
            result,
            {
                "ip_address": "71.6.135.131",
                "classification": "benign",
                "name": "Shodan.io",
                "link": "https://viz.greynoise.io/ip/71.6.135.131",
                "last_seen": "2026-06-10",
            },
        )
        self.assertEqual(client.calls[0]["ip_address"], "71.6.135.131")

    def test_enrich_with_shodan_returns_expected_projection(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("shodan-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="shodan",
                label="Shodan",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeShodanClient(payload=build_shodan_payload())
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
            client,
        )

        result = service.enrich_with_shodan(ip_address="8.8.8.8")

        self.assertEqual(result["ip_address"], "8.8.8.8")
        self.assertEqual(result["organization"], "Google")
        self.assertEqual(result["asn"], "AS15169")
        self.assertEqual(result["country_name"], "United States")
        self.assertEqual(result["hostnames"], ["dns.google"])
        self.assertEqual(result["exposed_ports"], ["53/udp", "443/tcp", "80/tcp"])
        self.assertEqual(result["services"], ["DNS", "HTTPS", "HTTP"])
        self.assertEqual(result["known_vulnerabilities_count"], 3)
        self.assertEqual(
            result["vulnerabilities"],
            ["CVE-2024-0001", "CVE-2024-0002", "CVE-2023-9999"],
        )
        self.assertEqual(
            result["last_observed_at"],
            datetime(2026, 6, 10, 8, 49, 35, 190817, tzinfo=UTC),
        )
        self.assertEqual(client.calls[0]["ip_address"], "8.8.8.8")
        self.assertFalse(client.calls[0]["minify"])

    def test_enrich_with_rdap_returns_expected_projection_without_api_key(self) -> None:
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="rdap",
                label="RDAP / WHOIS",
                is_key_required=False,
                encrypted_api_key=None,
            )
        )
        client = FakeRdapClient(payload=build_rdap_payload())
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            client,
            self.virustotal_client,
        )

        result = service.enrich_with_rdap(ip_address="8.8.8.8")

        self.assertEqual(
            result,
            {
                "ip_address": "8.8.8.8",
                "name": "GOGL",
                "country": "United States",
                "abuse_contact_email": "abuse@google.example",
                "start_address": "8.8.8.0",
                "end_address": "8.8.8.255",
            },
        )
        self.assertEqual(client.calls[0]["ip_address"], "8.8.8.8")

    def test_enrich_with_virustotal_returns_expected_projection(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("virustotal-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="virustotal",
                label="VirusTotal",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeVirusTotalClient(payload=build_virustotal_payload())
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            client,
        )

        result = service.enrich_with_virustotal(ip_address="8.8.8.8")

        self.assertEqual(result["ip_address"], "8.8.8.8")
        self.assertEqual(result["reputation"], -12)
        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["as_owner"], "Google LLC")
        self.assertEqual(
            result["last_analysis_stats"],
            {
                "malicious": 3,
                "suspicious": 1,
                "harmless": 12,
                "undetected": 54,
                "timeout": 0,
            },
        )
        self.assertEqual(client.calls[0]["ip_address"], "8.8.8.8")

    def test_enrich_with_virustotal_defaults_missing_fields(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("virustotal-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="virustotal",
                label="VirusTotal",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeVirusTotalClient(payload={})
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            client,
        )

        result = service.enrich_with_virustotal(ip_address="8.8.8.8")

        self.assertEqual(
            result,
            {
                "ip_address": "8.8.8.8",
                "reputation": 0,
                "country_code": None,
                "as_owner": None,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "timeout": 0,
                },
            },
        )

    def test_enrich_with_abuseipdb_rejects_inactive_provider(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("abuseipdb-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                encrypted_api_key=encrypted_api_key,
                is_active=False,
            )
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        with self.assertRaises(BadRequestError) as context:
            service.enrich_with_abuseipdb(ip_address="8.8.8.8", max_age_in_days=30)

        self.assertEqual(context.exception.code, "cti_provider_inactive")

    def test_enrich_with_abuseipdb_rejects_missing_api_key(self) -> None:
        repository = FakeCtiConfigRepository(build_cti_row(encrypted_api_key=None))
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        with self.assertRaises(BadRequestError) as context:
            service.enrich_with_abuseipdb(ip_address="8.8.8.8", max_age_in_days=30)

        self.assertEqual(context.exception.code, "cti_provider_not_configured")

    def test_enrich_with_abuseipdb_returns_not_found_when_config_is_missing(self) -> None:
        service = CtiEnrichmentService(
            FakeCtiConfigRepository(None),
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        with self.assertRaises(NotFoundError) as context:
            service.enrich_with_abuseipdb(ip_address="8.8.8.8", max_age_in_days=30)

        self.assertEqual(context.exception.code, "cti_config_not_found")

    def test_enrich_with_abuseipdb_maps_external_errors(self) -> None:
        client = FakeAbuseIpdbClient(
            error=IntegrationRequestError("rate_limit", "rate limit", status_code=429)
        )
        service = CtiEnrichmentService(
            self.repository,
            self.secret_service,
            client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        with self.assertRaises(ServiceUnavailableError) as context:
            service.enrich_with_abuseipdb(ip_address="8.8.8.8", max_age_in_days=30)

        self.assertEqual(context.exception.code, "cti_enrichment_unavailable")
        self.assertIn("rate limit", context.exception.message.lower())

    def test_enrich_with_ipdata_maps_external_errors(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("ipdata-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="ipdata",
                label="IPData",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeIpDataClient(
            error=IntegrationRequestError("auth_rejected", "auth rejected", status_code=401)
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        with self.assertRaises(ServiceUnavailableError) as context:
            service.enrich_with_ipdata(ip_address="8.8.8.8")

        self.assertEqual(context.exception.code, "cti_enrichment_unavailable")
        self.assertIn("rejected", context.exception.message.lower())

    def test_enrich_with_greynoise_maps_external_errors(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("greynoise-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="greynoise",
                label="GreyNoise",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeGreyNoiseClient(
            error=IntegrationRequestError("service_unavailable", "service unavailable")
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            client,
            self.rdap_client,
            self.virustotal_client,
        )

        with self.assertRaises(ServiceUnavailableError) as context:
            service.enrich_with_greynoise(ip_address="71.6.135.131")

        self.assertEqual(context.exception.code, "cti_enrichment_unavailable")
        self.assertIn("service is unavailable", context.exception.message.lower())

    def test_enrich_with_shodan_maps_external_errors(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("shodan-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="shodan",
                label="Shodan",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeShodanClient(
            error=IntegrationRequestError("service_unavailable", "service unavailable")
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
            client,
        )

        with self.assertRaises(ServiceUnavailableError) as context:
            service.enrich_with_shodan(ip_address="8.8.8.8")

        self.assertEqual(context.exception.code, "cti_enrichment_unavailable")
        self.assertIn("service is unavailable", context.exception.message.lower())

    def test_enrich_with_rdap_maps_external_errors(self) -> None:
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="rdap",
                label="RDAP / WHOIS",
                is_key_required=False,
                encrypted_api_key=None,
            )
        )
        client = FakeRdapClient(
            error=IntegrationRequestError("timeout", "timeout")
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            client,
            self.virustotal_client,
        )

        with self.assertRaises(ServiceUnavailableError) as context:
            service.enrich_with_rdap(ip_address="8.8.8.8")

        self.assertEqual(context.exception.code, "cti_enrichment_unavailable")
        self.assertIn("timed out", context.exception.message.lower())

    def test_enrich_with_rdap_defaults_missing_optional_fields(self) -> None:
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="rdap",
                label="RDAP / WHOIS",
                is_key_required=False,
                encrypted_api_key=None,
            )
        )
        client = FakeRdapClient(
            payload={
                "handle": "1.1.1.1",
                "name": "CLOUDFLARENET",
                "startAddress": "1.1.1.0",
                "endAddress": "1.1.1.255",
            }
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            client,
            self.virustotal_client,
        )

        result = service.enrich_with_rdap(ip_address="1.1.1.1")

        self.assertEqual(
            result,
            {
                "ip_address": "1.1.1.1",
                "name": "CLOUDFLARENET",
                "country": None,
                "abuse_contact_email": None,
                "start_address": "1.1.1.0",
                "end_address": "1.1.1.255",
            },
        )

    def test_enrich_with_virustotal_maps_external_errors(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("virustotal-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="virustotal",
                label="VirusTotal",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeVirusTotalClient(
            error=IntegrationRequestError("timeout", "timeout")
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            client,
        )

        with self.assertRaises(ServiceUnavailableError) as context:
            service.enrich_with_virustotal(ip_address="8.8.8.8")

        self.assertEqual(context.exception.code, "cti_enrichment_unavailable")
        self.assertIn("timed out", context.exception.message.lower())

    def test_enrich_with_virustotal_rejects_invalid_payload(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("virustotal-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="virustotal",
                label="VirusTotal",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeVirusTotalClient(payload=[])
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            client,
        )

        with self.assertRaises(ServiceUnavailableError) as context:
            service.enrich_with_virustotal(ip_address="8.8.8.8")

        self.assertEqual(context.exception.code, "cti_enrichment_invalid_response")

    def test_enrich_with_ipdata_defaults_missing_nested_fields(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("ipdata-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="ipdata",
                label="IPData",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeIpDataClient(
            payload={
                "ip": "1.1.1.1",
                "country_name": None,
            }
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
        )

        result = service.enrich_with_ipdata(ip_address="1.1.1.1")

        self.assertEqual(
            result,
            {
                "ip_address": "1.1.1.1",
                "country_name": None,
                "asn_name": None,
                "is_threat": False,
            },
        )

    def test_enrich_with_shodan_defaults_missing_optional_fields(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("shodan-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="shodan",
                label="Shodan",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeShodanClient(payload={"ip_str": "1.1.1.1"})
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            self.greynoise_client,
            self.rdap_client,
            self.virustotal_client,
            client,
        )

        result = service.enrich_with_shodan(ip_address="1.1.1.1")

        self.assertEqual(
            result,
            {
                "ip_address": "1.1.1.1",
                "organization": None,
                "asn": None,
                "country_name": None,
                "hostnames": [],
                "exposed_ports": [],
                "services": [],
                "known_vulnerabilities_count": 0,
                "vulnerabilities": [],
                "last_observed_at": None,
            },
        )

    def test_enrich_with_greynoise_defaults_missing_optional_fields(self) -> None:
        encrypted_api_key = self.secret_service.encrypt_secret("greynoise-api-key")
        repository = FakeCtiConfigRepository(
            build_cti_row(
                code="greynoise",
                label="GreyNoise",
                encrypted_api_key=encrypted_api_key,
            )
        )
        client = FakeGreyNoiseClient(
            payload={
                "ip": "1.1.1.1",
            }
        )
        service = CtiEnrichmentService(
            repository,
            self.secret_service,
            self.abuseipdb_client,
            self.ipdata_client,
            client,
            self.rdap_client,
            self.virustotal_client,
        )

        result = service.enrich_with_greynoise(ip_address="1.1.1.1")

        self.assertEqual(
            result,
            {
                "ip_address": "1.1.1.1",
                "classification": None,
                "name": None,
                "link": None,
                "last_seen": None,
            },
        )
