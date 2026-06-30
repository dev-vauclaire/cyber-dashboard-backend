"""Dependances FastAPI partagees."""

from __future__ import annotations

from functools import lru_cache

from cyber_dashboard_api.config import get_settings
from cyber_dashboard_api.db import get_database
from cyber_dashboard_api.integrations.attacks_collectors.registry import (
    AttacksCollectorValidatorRegistry,
)
from cyber_dashboard_api.integrations.cti.clients.abuseipdb_client import (
    AbuseIpdbClient,
)
from cyber_dashboard_api.integrations.cti.clients.greynoise_client import (
    GreyNoiseClient,
)
from cyber_dashboard_api.integrations.cti.clients.ipdata_client import IpDataClient
from cyber_dashboard_api.integrations.cti.clients.ipinfo_client import IpinfoClient
from cyber_dashboard_api.integrations.cti.clients.rdap_client import RdapClient
from cyber_dashboard_api.integrations.cti.clients.shodan_client import ShodanClient
from cyber_dashboard_api.integrations.cti.clients.virustotal_client import (
    VirusTotalClient,
)
from cyber_dashboard_api.integrations.cti.registry import CtiValidatorRegistry
from cyber_dashboard_api.integrations.smtp.validator import SmtpValidator
from cyber_dashboard_api.repositories import (
    AlertRepository,
    AttackRepository,
    AttacksCollectorConfigRepository,
    CtiConfigRepository,
    DashboardRepository,
    RetentionPolicyRepository,
    SensorTypeRepository,
    SourceRepository,
    SmtpConfigRepository,
    StatisticsRepository,
)
from cyber_dashboard_api.services import (
    AlertEmailService,
    AttacksCollectorConfigService,
    CtiConfigService,
    CtiEnrichmentService,
    RetentionPolicyService,
    SecretService,
    SensorTypeService,
    SmtpConfigService,
    SmtpEmailService,
    SourceService,
)


def get_dashboard_repository() -> DashboardRepository:
    """Construit le repository de lecture du dashboard."""
    return DashboardRepository(get_database())


def get_source_repository() -> SourceRepository:
    """Construit le repository de lecture des sources."""
    return SourceRepository(get_database())


def get_sensor_type_repository() -> SensorTypeRepository:
    """Construit le repository de lecture des types de capteurs."""
    return SensorTypeRepository(get_database())


def get_source_service() -> SourceService:
    """Construit le service metier des sources."""
    return SourceService(get_source_repository())


def get_sensor_type_service() -> SensorTypeService:
    """Construit le service metier des types de capteurs."""
    return SensorTypeService(get_sensor_type_repository())


def get_alert_repository() -> AlertRepository:
    """Construit le repository de lecture des alertes."""
    return AlertRepository(get_database())


def get_attack_repository() -> AttackRepository:
    """Construit le repository de lecture des attaques."""
    return AttackRepository(get_database())


def get_statistics_repository() -> StatisticsRepository:
    """Construit le repository de lecture des statistiques."""
    return StatisticsRepository(get_database())


def get_cti_config_repository() -> CtiConfigRepository:
    """Construit le repository des configurations CTI."""
    return CtiConfigRepository(get_database())


def get_smtp_config_repository() -> SmtpConfigRepository:
    """Construit le repository de configuration SMTP."""
    return SmtpConfigRepository(get_database())


def get_attacks_collector_config_repository() -> AttacksCollectorConfigRepository:
    """Construit le repository des collecteurs d'attaques."""
    return AttacksCollectorConfigRepository(get_database())


def get_retention_policy_repository() -> RetentionPolicyRepository:
    """Construit le repository des politiques de retention."""
    return RetentionPolicyRepository(get_database())


@lru_cache(maxsize=1)
def get_secret_service() -> SecretService:
    """Construit un service unique de chiffrement des secrets."""
    return SecretService(get_settings().secrets)


@lru_cache(maxsize=1)
def get_cti_validator_registry() -> CtiValidatorRegistry:
    """Construit le registry des validateurs CTI."""
    return CtiValidatorRegistry(get_settings().validation)


@lru_cache(maxsize=1)
def get_abuseipdb_client() -> AbuseIpdbClient:
    """Construit le client AbuseIPDB partage."""
    return AbuseIpdbClient(timeout_seconds=get_settings().validation.timeout_seconds)


@lru_cache(maxsize=1)
def get_ipdata_client() -> IpDataClient:
    """Construit le client IPData partage."""
    return IpDataClient(timeout_seconds=get_settings().validation.timeout_seconds)


@lru_cache(maxsize=1)
def get_ipinfo_client() -> IpinfoClient:
    """Construit le client IPinfo partage."""
    return IpinfoClient(timeout_seconds=get_settings().validation.timeout_seconds)


@lru_cache(maxsize=1)
def get_greynoise_client() -> GreyNoiseClient:
    """Construit le client GreyNoise partage."""
    return GreyNoiseClient(timeout_seconds=get_settings().validation.timeout_seconds)


@lru_cache(maxsize=1)
def get_rdap_client() -> RdapClient:
    """Construit le client RDAP partage."""
    return RdapClient(timeout_seconds=get_settings().validation.timeout_seconds)


@lru_cache(maxsize=1)
def get_shodan_client() -> ShodanClient:
    """Construit le client Shodan partage."""
    return ShodanClient(timeout_seconds=get_settings().validation.timeout_seconds)


@lru_cache(maxsize=1)
def get_virustotal_client() -> VirusTotalClient:
    """Construit le client VirusTotal partage."""
    return VirusTotalClient(timeout_seconds=get_settings().validation.timeout_seconds)


@lru_cache(maxsize=1)
def get_attacks_collector_validator_registry() -> AttacksCollectorValidatorRegistry:
    """Construit le registry des validateurs de collecteurs."""
    return AttacksCollectorValidatorRegistry(get_settings().validation)


@lru_cache(maxsize=1)
def get_smtp_validator() -> SmtpValidator:
    """Construit le validateur SMTP."""
    return SmtpValidator()


def get_cti_config_service() -> CtiConfigService:
    """Construit le service metier des configurations CTI."""
    return CtiConfigService(
        get_cti_config_repository(),
        get_secret_service(),
        get_cti_validator_registry(),
        get_settings().validation,
    )


def get_cti_enrichment_service() -> CtiEnrichmentService:
    """Construit le service metier d'enrichissement CTI."""
    return CtiEnrichmentService(
        get_cti_config_repository(),
        get_secret_service(),
        get_abuseipdb_client(),
        get_ipdata_client(),
        get_greynoise_client(),
        get_rdap_client(),
        get_virustotal_client(),
        get_shodan_client(),
        get_ipinfo_client(),
    )


def get_smtp_config_service() -> SmtpConfigService:
    """Construit le service metier de configuration SMTP."""
    return SmtpConfigService(
        get_smtp_config_repository(),
        get_secret_service(),
        get_smtp_validator(),
        get_settings().validation,
    )


def get_smtp_email_service() -> SmtpEmailService:
    """Construit le service generique d'envoi SMTP."""
    return SmtpEmailService(
        get_smtp_config_repository(),
        get_secret_service(),
        get_settings().validation,
    )


def get_alert_email_service() -> AlertEmailService:
    """Construit le service d'envoi manuel d'emails d'alerte."""
    return AlertEmailService(
        get_alert_repository(),
        get_smtp_email_service(),
    )


def get_attacks_collector_config_service() -> AttacksCollectorConfigService:
    """Construit le service metier des collecteurs d'attaques."""
    return AttacksCollectorConfigService(
        get_attacks_collector_config_repository(),
        get_secret_service(),
        get_attacks_collector_validator_registry(),
    )


def get_retention_policy_service() -> RetentionPolicyService:
    """Construit le service metier des politiques de retention."""
    return RetentionPolicyService(get_retention_policy_repository())
