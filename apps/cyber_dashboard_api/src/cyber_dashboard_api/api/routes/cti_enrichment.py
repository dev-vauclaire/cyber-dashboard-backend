"""Routes REST pour les enrichissements CTI."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv6Address

from fastapi import APIRouter, Depends, Query

from cyber_dashboard_api.api.dependencies import get_cti_enrichment_service
from cyber_dashboard_api.api.schemas import (
    AbuseIpdbEnrichmentResponseSchema,
    GreyNoiseEnrichmentResponseSchema,
    IpDataEnrichmentResponseSchema,
    IpinfoEnrichmentResponseSchema,
    RdapEnrichmentResponseSchema,
    ShodanEnrichmentResponseSchema,
    VirusTotalEnrichmentResponseSchema,
)
from cyber_dashboard_api.services import CtiEnrichmentService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cti-enrichment", tags=["cti-enrichment"])


@router.get("/abuseipdb", response_model=AbuseIpdbEnrichmentResponseSchema)
def get_abuseipdb_enrichment(
    ip_address: IPv4Address | IPv6Address,
    max_age_in_days: int = Query(default=30, ge=1, le=365),
    cti_enrichment_service: CtiEnrichmentService = Depends(get_cti_enrichment_service),
) -> AbuseIpdbEnrichmentResponseSchema:
    """Retourne l'enrichissement AbuseIPDB d'une adresse IP."""
    logger.info(
        "endpoint=cti_enrichment_abuseipdb event=requested ip_address=%s max_age_in_days=%s",
        ip_address,
        max_age_in_days,
    )
    payload = cti_enrichment_service.enrich_with_abuseipdb(
        ip_address=str(ip_address),
        max_age_in_days=max_age_in_days,
    )
    return AbuseIpdbEnrichmentResponseSchema(**payload)


@router.get("/ipdata", response_model=IpDataEnrichmentResponseSchema)
def get_ipdata_enrichment(
    ip_address: IPv4Address | IPv6Address,
    cti_enrichment_service: CtiEnrichmentService = Depends(get_cti_enrichment_service),
) -> IpDataEnrichmentResponseSchema:
    """Retourne l'enrichissement IPData d'une adresse IP."""
    logger.info(
        "endpoint=cti_enrichment_ipdata event=requested ip_address=%s",
        ip_address,
    )
    payload = cti_enrichment_service.enrich_with_ipdata(
        ip_address=str(ip_address),
    )
    return IpDataEnrichmentResponseSchema(**payload)


@router.get("/ipinfo", response_model=IpinfoEnrichmentResponseSchema)
def get_ipinfo_enrichment(
    ip_address: IPv4Address | IPv6Address,
    cti_enrichment_service: CtiEnrichmentService = Depends(get_cti_enrichment_service),
) -> IpinfoEnrichmentResponseSchema:
    """Retourne l'enrichissement IPinfo Lite d'une adresse IP."""
    logger.info(
        "endpoint=cti_enrichment_ipinfo event=requested ip_address=%s",
        ip_address,
    )
    payload = cti_enrichment_service.enrich_with_ipinfo(
        ip_address=str(ip_address),
    )
    return IpinfoEnrichmentResponseSchema(**payload)


@router.get("/greynoise", response_model=GreyNoiseEnrichmentResponseSchema)
def get_greynoise_enrichment(
    ip_address: IPv4Address | IPv6Address,
    cti_enrichment_service: CtiEnrichmentService = Depends(get_cti_enrichment_service),
) -> GreyNoiseEnrichmentResponseSchema:
    """Retourne l'enrichissement GreyNoise d'une adresse IP."""
    logger.info(
        "endpoint=cti_enrichment_greynoise event=requested ip_address=%s",
        ip_address,
    )
    payload = cti_enrichment_service.enrich_with_greynoise(
        ip_address=str(ip_address),
    )
    return GreyNoiseEnrichmentResponseSchema(**payload)


@router.get("/rdap", response_model=RdapEnrichmentResponseSchema)
def get_rdap_enrichment(
    ip_address: IPv4Address | IPv6Address,
    cti_enrichment_service: CtiEnrichmentService = Depends(get_cti_enrichment_service),
) -> RdapEnrichmentResponseSchema:
    """Retourne l'enrichissement RDAP d'une adresse IP."""
    logger.info(
        "endpoint=cti_enrichment_rdap event=requested ip_address=%s",
        ip_address,
    )
    payload = cti_enrichment_service.enrich_with_rdap(
        ip_address=str(ip_address),
    )
    return RdapEnrichmentResponseSchema(**payload)


@router.get("/shodan", response_model=ShodanEnrichmentResponseSchema)
def get_shodan_enrichment(
    ip_address: IPv4Address | IPv6Address,
    cti_enrichment_service: CtiEnrichmentService = Depends(get_cti_enrichment_service),
) -> ShodanEnrichmentResponseSchema:
    """Retourne l'enrichissement Shodan d'une adresse IP."""
    logger.info(
        "endpoint=cti_enrichment_shodan event=requested ip_address=%s",
        ip_address,
    )
    payload = cti_enrichment_service.enrich_with_shodan(
        ip_address=str(ip_address),
    )
    return ShodanEnrichmentResponseSchema(**payload)


@router.get("/virustotal", response_model=VirusTotalEnrichmentResponseSchema)
def get_virustotal_enrichment(
    ip_address: IPv4Address | IPv6Address,
    cti_enrichment_service: CtiEnrichmentService = Depends(get_cti_enrichment_service),
) -> VirusTotalEnrichmentResponseSchema:
    """Retourne l'enrichissement VirusTotal d'une adresse IP."""
    logger.info(
        "endpoint=cti_enrichment_virustotal event=requested ip_address=%s",
        ip_address,
    )
    payload = cti_enrichment_service.enrich_with_virustotal(
        ip_address=str(ip_address),
    )
    return VirusTotalEnrichmentResponseSchema(**payload)
