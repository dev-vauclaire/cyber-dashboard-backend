"""Schemas API pour les routes d'enrichissement CTI."""

from __future__ import annotations

from datetime import date, datetime

from .common import ApiSchema


class AbuseIpdbCategoryPercentageSchema(ApiSchema):
    """Pourcentage d'occurrence d'une categorie AbuseIPDB."""

    category_code: int
    percentage: float


class AbuseIpdbEnrichmentResponseSchema(ApiSchema):
    """Representation publique d'un enrichissement AbuseIPDB."""

    ip_address: str
    abuse_confidence_score: int
    country_code: str | None
    isp: str | None
    last_reported_at: datetime | None
    total_reports: int
    category_percentages: list[AbuseIpdbCategoryPercentageSchema]


class VirusTotalAnalysisStatsSchema(ApiSchema):
    """Synthese des statuts d'analyse VirusTotal."""

    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int


class VirusTotalEnrichmentResponseSchema(ApiSchema):
    """Representation publique d'un enrichissement VirusTotal."""

    ip_address: str
    reputation: int
    country_code: str | None
    as_owner: str | None
    last_analysis_stats: VirusTotalAnalysisStatsSchema


class IpDataEnrichmentResponseSchema(ApiSchema):
    """Representation publique d'un enrichissement IPData."""

    ip_address: str
    country_name: str | None
    asn_name: str | None
    is_threat: bool


class IpinfoEnrichmentResponseSchema(ApiSchema):
    """Representation publique d'un enrichissement IPinfo Lite."""

    ip_address: str
    asn: str | None
    as_name: str | None
    as_domain: str | None
    country_code: str | None
    country: str | None
    continent_code: str | None
    continent: str | None


class RdapEnrichmentResponseSchema(ApiSchema):
    """Representation publique d'un enrichissement RDAP."""

    ip_address: str
    name: str | None
    country: str | None
    abuse_contact_email: str | None
    start_address: str | None
    end_address: str | None


class GreyNoiseEnrichmentResponseSchema(ApiSchema):
    """Representation publique d'un enrichissement GreyNoise."""

    ip_address: str
    classification: str | None
    name: str | None
    link: str | None
    last_seen: date | None


class ShodanEnrichmentResponseSchema(ApiSchema):
    """Representation publique d'un enrichissement Shodan."""

    ip_address: str
    organization: str | None
    asn: str | None
    country_name: str | None
    hostnames: list[str]
    exposed_ports: list[str]
    services: list[str]
    known_vulnerabilities_count: int
    vulnerabilities: list[str]
    last_observed_at: datetime | None
