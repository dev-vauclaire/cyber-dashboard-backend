"""Service metier pour les routes d'enrichissement CTI."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from cyber_dashboard_api.api.errors import (
    BadRequestError,
    NotFoundError,
    ServiceUnavailableError,
)
from cyber_dashboard_api.integrations.common import IntegrationRequestError
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
from cyber_dashboard_api.repositories import CtiConfigRepository
from cyber_dashboard_api.services.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)

ABUSEIPDB_PROVIDER_CODE = "abuseipdb"
GREYNOISE_PROVIDER_CODE = "greynoise"
IPDATA_PROVIDER_CODE = "ipdata"
IPINFO_PROVIDER_CODE = "ipinfo"
RDAP_PROVIDER_CODE = "rdap"
SHODAN_PROVIDER_CODE = "shodan"
VIRUSTOTAL_PROVIDER_CODE = "virustotal"


class CtiEnrichmentService:
    """Encapsule les appels d'enrichissement CTI exposes par l'API."""

    def __init__(
        self,
        repository: CtiConfigRepository,
        secret_service: SecretService,
        abuseipdb_client: AbuseIpdbClient,
        ipdata_client: IpDataClient,
        greynoise_client: GreyNoiseClient,
        rdap_client: RdapClient,
        virustotal_client: VirusTotalClient,
        shodan_client: ShodanClient | None = None,
        ipinfo_client: IpinfoClient | None = None,
    ) -> None:
        self._repository = repository
        self._secret_service = secret_service
        self._abuseipdb_client = abuseipdb_client
        self._ipdata_client = ipdata_client
        self._greynoise_client = greynoise_client
        self._rdap_client = rdap_client
        self._virustotal_client = virustotal_client
        self._shodan_client = shodan_client
        self._ipinfo_client = ipinfo_client

    def enrich_with_abuseipdb(
        self,
        *,
        ip_address: str,
        max_age_in_days: int,
    ) -> dict[str, Any]:
        """Retourne l'enrichissement AbuseIPDB d'une adresse IP."""
        api_key = self._load_active_api_key(ABUSEIPDB_PROVIDER_CODE)

        try:
            payload, _ = self._abuseipdb_client.get_ip_report(
                api_key=api_key,
                ip_address=ip_address,
                max_age_in_days=max_age_in_days,
                verbose=True,
            )
        except IntegrationRequestError as exc:
            self._raise_enrichment_request_error("AbuseIPDB", exc)

        return self._map_abuseipdb_payload(ip_address=ip_address, payload=payload)

    def enrich_with_ipdata(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        """Retourne l'enrichissement IPData d'une adresse IP."""
        api_key = self._load_active_api_key(IPDATA_PROVIDER_CODE)

        try:
            payload, _ = self._ipdata_client.get_ip_report(
                api_key=api_key,
                ip_address=ip_address,
            )
        except IntegrationRequestError as exc:
            self._raise_enrichment_request_error("IPData", exc)

        return self._map_ipdata_payload(ip_address=ip_address, payload=payload)

    def enrich_with_greynoise(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        """Retourne l'enrichissement GreyNoise d'une adresse IP."""
        api_key = self._load_active_api_key(GREYNOISE_PROVIDER_CODE)

        try:
            payload, _ = self._greynoise_client.get_ip_report(
                api_key=api_key,
                ip_address=ip_address,
            )
        except IntegrationRequestError as exc:
            self._raise_enrichment_request_error("GreyNoise", exc)

        return self._map_greynoise_payload(ip_address=ip_address, payload=payload)

    def enrich_with_ipinfo(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        """Retourne l'enrichissement IPinfo Lite d'une adresse IP."""
        api_key = self._load_active_api_key(IPINFO_PROVIDER_CODE)
        if self._ipinfo_client is None:
            raise ServiceUnavailableError(
                code="cti_enrichment_unavailable",
                message="Le client IPinfo n'est pas configuré",
            )

        try:
            payload, _ = self._ipinfo_client.get_ip_report(
                api_key=api_key,
                ip_address=ip_address,
            )
        except IntegrationRequestError as exc:
            self._raise_enrichment_request_error("IPinfo", exc)

        return self._map_ipinfo_payload(ip_address=ip_address, payload=payload)

    def enrich_with_rdap(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        """Retourne l'enrichissement RDAP d'une adresse IP."""
        self._load_active_provider_config(RDAP_PROVIDER_CODE)

        try:
            payload, _ = self._rdap_client.get_ip_report(
                ip_address=ip_address,
            )
        except IntegrationRequestError as exc:
            self._raise_enrichment_request_error("RDAP", exc)

        return self._map_rdap_payload(ip_address=ip_address, payload=payload)

    def enrich_with_shodan(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        """Retourne l'enrichissement Shodan d'une adresse IP."""
        api_key = self._load_active_api_key(SHODAN_PROVIDER_CODE)
        if self._shodan_client is None:
            raise ServiceUnavailableError(
                code="cti_enrichment_unavailable",
                message="Le client Shodan n'est pas configuré",
            )

        try:
            payload, _ = self._shodan_client.get_host_report(
                api_key=api_key,
                ip_address=ip_address,
            )
        except IntegrationRequestError as exc:
            self._raise_enrichment_request_error("Shodan", exc)

        return self._map_shodan_payload(ip_address=ip_address, payload=payload)

    def enrich_with_virustotal(
        self,
        *,
        ip_address: str,
    ) -> dict[str, Any]:
        """Retourne l'enrichissement VirusTotal d'une adresse IP."""
        api_key = self._load_active_api_key(VIRUSTOTAL_PROVIDER_CODE)

        try:
            payload, _ = self._virustotal_client.get_ip_report(
                api_key=api_key,
                ip_address=ip_address,
            )
        except IntegrationRequestError as exc:
            self._raise_enrichment_request_error("VirusTotal", exc)

        return self._map_virustotal_payload(ip_address=ip_address, payload=payload)

    def _load_active_provider_config(self, code: str) -> dict[str, Any]:
        row = self._repository.get_by_code(code)
        if row is None:
            raise NotFoundError(
                code="cti_config_not_found",
                message="Configuration CTI introuvable",
            )

        if not bool(row.get("is_active")):
            raise BadRequestError(
                code="cti_provider_inactive",
                message=f"Le fournisseur CTI '{code}' n'est pas actif",
            )

        return row

    def _load_active_api_key(self, code: str) -> str:
        row = self._load_active_provider_config(code)
        encrypted_api_key = row.get("encrypted_api_key")
        if not self._secret_service.has_secret(encrypted_api_key):
            raise BadRequestError(
                code="cti_provider_not_configured",
                message=f"Le fournisseur CTI '{code}' n'a pas de clé API",
            )

        try:
            return self._secret_service.decrypt_secret(str(encrypted_api_key))
        except (SecretConfigurationError, SecretDecryptionError) as exc:
            raise ServiceUnavailableError(
                code="secret_key_unavailable",
                message="Le secret CTI stocké n'a pas pu être déchiffré",
            ) from exc

    @staticmethod
    def _map_abuseipdb_payload(
        *,
        ip_address: str,
        payload: object,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ServiceUnavailableError(
                code="cti_enrichment_invalid_response",
                message="AbuseIPDB a renvoyé une réponse inattendue",
            )

        data = CtiEnrichmentService._coerce_dict(payload.get("data"))
        total_reports = CtiEnrichmentService._coerce_int(data.get("totalReports"))
        reports = data.get("reports")
        category_percentages = (
            CtiEnrichmentService._compute_abuseipdb_category_percentages(
                reports=reports,
                total_reports=total_reports,
            )
        )

        return {
            "ip_address": str(data.get("ipAddress") or ip_address),
            "abuse_confidence_score": CtiEnrichmentService._coerce_int(
                data.get("abuseConfidenceScore")
            ),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "last_reported_at": data.get("lastReportedAt"),
            "total_reports": total_reports,
            "category_percentages": category_percentages,
        }

    @staticmethod
    def _map_virustotal_payload(
        *,
        ip_address: str,
        payload: object,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ServiceUnavailableError(
                code="cti_enrichment_invalid_response",
                message="VirusTotal a renvoyé une réponse inattendue",
            )

        data = CtiEnrichmentService._coerce_dict(payload.get("data"))
        attributes = CtiEnrichmentService._coerce_dict(data.get("attributes"))
        stats = CtiEnrichmentService._coerce_dict(attributes.get("last_analysis_stats"))

        return {
            "ip_address": str(data.get("id") or ip_address),
            "reputation": CtiEnrichmentService._coerce_int(
                attributes.get("reputation")
            ),
            "country_code": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "last_analysis_stats": {
                "malicious": CtiEnrichmentService._coerce_int(stats.get("malicious")),
                "suspicious": CtiEnrichmentService._coerce_int(stats.get("suspicious")),
                "harmless": CtiEnrichmentService._coerce_int(stats.get("harmless")),
                "undetected": CtiEnrichmentService._coerce_int(stats.get("undetected")),
                "timeout": CtiEnrichmentService._coerce_int(stats.get("timeout")),
            },
        }

    @staticmethod
    def _map_ipdata_payload(
        *,
        ip_address: str,
        payload: object,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ServiceUnavailableError(
                code="cti_enrichment_invalid_response",
                message="IPData a renvoyé une réponse inattendue",
            )

        asn = CtiEnrichmentService._coerce_dict(payload.get("asn"))
        threat = CtiEnrichmentService._coerce_dict(payload.get("threat"))

        return {
            "ip_address": str(payload.get("ip") or ip_address),
            "country_name": payload.get("country_name"),
            "asn_name": asn.get("name"),
            "is_threat": CtiEnrichmentService._coerce_bool(threat.get("is_threat")),
        }

    @staticmethod
    def _map_greynoise_payload(
        *,
        ip_address: str,
        payload: object,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ServiceUnavailableError(
                code="cti_enrichment_invalid_response",
                message="GreyNoise a renvoyé une réponse inattendue",
            )

        return {
            "ip_address": str(payload.get("ip") or ip_address),
            "classification": payload.get("classification"),
            "name": payload.get("name"),
            "link": payload.get("link"),
            "last_seen": payload.get("last_seen"),
        }

    @staticmethod
    def _map_ipinfo_payload(
        *,
        ip_address: str,
        payload: object,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ServiceUnavailableError(
                code="cti_enrichment_invalid_response",
                message="IPinfo a renvoyé une réponse inattendue",
            )

        return {
            "ip_address": str(payload.get("ip") or ip_address),
            "asn": payload.get("asn"),
            "as_name": payload.get("as_name"),
            "as_domain": payload.get("as_domain"),
            "country_code": payload.get("country_code"),
            "country": payload.get("country"),
            "continent_code": payload.get("continent_code"),
            "continent": payload.get("continent"),
        }

    @staticmethod
    def _map_rdap_payload(
        *,
        ip_address: str,
        payload: object,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ServiceUnavailableError(
                code="cti_enrichment_invalid_response",
                message="RDAP a renvoyé une réponse inattendue",
            )

        entities = payload.get("entities")
        root_entities = entities if isinstance(entities, list) else []

        registrant_entity = next(
            (
                entity
                for entity in root_entities
                if isinstance(entity, dict)
                and CtiEnrichmentService._entity_has_role(entity, "registrant")
            ),
            None,
        )
        abuse_entity = next(
            (
                entity
                for entity in CtiEnrichmentService._iter_entities(root_entities)
                if CtiEnrichmentService._entity_has_role(entity, "abuse")
            ),
            None,
        )

        return {
            "ip_address": ip_address,
            "name": payload.get("name"),
            "country": CtiEnrichmentService._extract_country_from_entity(
                registrant_entity
            ),
            "abuse_contact_email": CtiEnrichmentService._extract_email_from_entity(
                abuse_entity
            ),
            "start_address": payload.get("startAddress"),
            "end_address": payload.get("endAddress"),
        }

    @staticmethod
    def _map_shodan_payload(
        *,
        ip_address: str,
        payload: object,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ServiceUnavailableError(
                code="cti_enrichment_invalid_response",
                message="Shodan a renvoyé une réponse inattendue",
            )

        items = payload.get("data")
        data_items = items if isinstance(items, list) else []

        hostnames = CtiEnrichmentService._collect_non_empty_strings(
            payload.get("hostnames")
        )
        exposed_ports: list[str] = []
        services: list[str] = []
        vulnerabilities = CtiEnrichmentService._extract_shodan_vulnerability_values(
            payload.get("vulns")
        )
        observed_at_candidates: list[datetime] = []

        last_update = CtiEnrichmentService._parse_datetime(payload.get("last_update"))
        if last_update is not None:
            observed_at_candidates.append(last_update)

        for item in data_items:
            if not isinstance(item, dict):
                continue

            port = CtiEnrichmentService._coerce_int(item.get("port"))
            transport = item.get("transport")
            transport_name = (
                transport.strip().lower()
                if isinstance(transport, str) and transport.strip()
                else "tcp"
            )
            if port > 0:
                exposed_ports.append(f"{port}/{transport_name}")

            module_name = CtiEnrichmentService._extract_shodan_module_name(item)
            service_name = CtiEnrichmentService._derive_shodan_service_name(
                module_name=module_name,
                item=item,
            )
            if service_name is not None:
                services.append(service_name)

            vulnerabilities.extend(
                CtiEnrichmentService._extract_shodan_vulnerability_values(
                    item.get("vulns")
                )
            )
            opts = CtiEnrichmentService._coerce_dict(item.get("opts"))
            vulnerabilities.extend(
                CtiEnrichmentService._extract_shodan_vulnerability_values(
                    opts.get("vulns")
                )
            )

            item_timestamp = CtiEnrichmentService._parse_datetime(item.get("timestamp"))
            if item_timestamp is not None:
                observed_at_candidates.append(item_timestamp)

        deduplicated_vulnerabilities = (
            CtiEnrichmentService._deduplicate_preserving_order(vulnerabilities)
        )

        return {
            "ip_address": str(payload.get("ip_str") or ip_address),
            "organization": payload.get("org"),
            "asn": payload.get("asn"),
            "country_name": payload.get("country_name"),
            "hostnames": CtiEnrichmentService._deduplicate_preserving_order(hostnames),
            "exposed_ports": CtiEnrichmentService._deduplicate_preserving_order(
                exposed_ports
            ),
            "services": CtiEnrichmentService._deduplicate_preserving_order(services),
            "known_vulnerabilities_count": len(deduplicated_vulnerabilities),
            "vulnerabilities": deduplicated_vulnerabilities,
            "last_observed_at": (
                max(observed_at_candidates) if observed_at_candidates else None
            ),
        }

    @staticmethod
    def _compute_abuseipdb_category_percentages(
        *,
        reports: object,
        total_reports: int,
    ) -> list[dict[str, Any]]:
        if total_reports <= 0 or not isinstance(reports, list):
            return []

        category_counts: Counter[int] = Counter()
        for report in reports:
            if not isinstance(report, dict):
                continue

            raw_categories = report.get("categories")
            if not isinstance(raw_categories, list):
                continue

            normalized_categories = {
                CtiEnrichmentService._coerce_int(category_code)
                for category_code in raw_categories
            }
            normalized_categories.discard(0)

            for category_code in normalized_categories:
                category_counts[category_code] += 1

        return [
            {
                "category_code": category_code,
                "percentage": round((count / total_reports) * 100, 2),
            }
            for category_code, count in sorted(category_counts.items())
        ]

    @staticmethod
    def _coerce_int(value: object) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _coerce_bool(value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return False

    @staticmethod
    def _iter_entities(entities: list[object]) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        for entity in entities:
            if not isinstance(entity, dict):
                continue

            collected.append(entity)
            nested_entities = entity.get("entities")
            if isinstance(nested_entities, list):
                collected.extend(CtiEnrichmentService._iter_entities(nested_entities))

        return collected

    @staticmethod
    def _entity_has_role(entity: dict[str, Any], role: str) -> bool:
        raw_roles = entity.get("roles")
        if isinstance(raw_roles, list):
            normalized_roles = {str(raw_role).strip().lower() for raw_role in raw_roles}
            return role.lower() in normalized_roles

        raw_role = entity.get("role")
        if isinstance(raw_role, str):
            return raw_role.strip().lower() == role.lower()

        return False

    @staticmethod
    def _extract_country_from_entity(entity: object) -> str | None:
        if not isinstance(entity, dict):
            return None

        vcard_entries = CtiEnrichmentService._extract_vcard_entries(
            entity.get("vcardArray")
        )
        for entry in vcard_entries:
            if not isinstance(entry, list) or len(entry) < 2 or entry[0] != "adr":
                continue

            parameters = entry[1]
            if not isinstance(parameters, dict):
                continue

            label = parameters.get("label")
            if not isinstance(label, str):
                continue

            lines = [line.strip() for line in label.split("\n") if line.strip()]
            if lines:
                return lines[-1]

        return None

    @staticmethod
    def _extract_email_from_entity(entity: object) -> str | None:
        if not isinstance(entity, dict):
            return None

        vcard_entries = CtiEnrichmentService._extract_vcard_entries(
            entity.get("vcardArray")
        )
        for entry in vcard_entries:
            if not isinstance(entry, list) or len(entry) < 4 or entry[0] != "email":
                continue

            value = entry[3]
            if isinstance(value, str) and value.strip():
                return value.strip()

        return None

    @staticmethod
    def _extract_vcard_entries(vcard_array: object) -> list[object]:
        if (
            isinstance(vcard_array, list)
            and len(vcard_array) >= 2
            and isinstance(vcard_array[1], list)
        ):
            return list(vcard_array[1])
        return []

    @staticmethod
    def _coerce_dict(value: object) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        return {}

    @staticmethod
    def _collect_non_empty_strings(value: object) -> list[str]:
        if not isinstance(value, list):
            return []

        collected: list[str] = []
        for item in value:
            if isinstance(item, str):
                normalized = item.strip()
                if normalized:
                    collected.append(normalized)
        return collected

    @staticmethod
    def _extract_shodan_module_name(item: dict[str, Any]) -> str | None:
        shodan_metadata = CtiEnrichmentService._coerce_dict(item.get("_shodan"))
        module_name = shodan_metadata.get("module")
        if isinstance(module_name, str):
            normalized = module_name.strip()
            if normalized:
                return normalized
        return None

    @staticmethod
    def _derive_shodan_service_name(
        *,
        module_name: str | None,
        item: dict[str, Any],
    ) -> str | None:
        normalized_module = (module_name or "").lower()
        if "dns" in normalized_module:
            return "DNS"
        if "https" in normalized_module:
            return "HTTPS"
        if "http" in normalized_module:
            return "HTTP"
        if item.get("ssl") is not None:
            return "TLS"
        if module_name is not None:
            return module_name
        return None

    @staticmethod
    def _extract_shodan_vulnerability_values(value: object) -> list[str]:
        if isinstance(value, dict):
            return CtiEnrichmentService._collect_non_empty_strings(list(value.keys()))
        if isinstance(value, list):
            return CtiEnrichmentService._collect_non_empty_strings(value)
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    @staticmethod
    def _deduplicate_preserving_order(values: list[str]) -> list[str]:
        seen: set[str] = set()
        collected: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            collected.append(value)
        return collected

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        if isinstance(value, datetime):
            return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

        if not isinstance(value, str):
            return None

        raw_value = value.strip()
        if not raw_value:
            return None

        candidate = raw_value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return None

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed

    @staticmethod
    def _raise_enrichment_request_error(
        provider_label: str,
        error: IntegrationRequestError,
    ) -> None:
        if error.kind == "auth_rejected":
            raise ServiceUnavailableError(
                code="cti_enrichment_unavailable",
                message=f"{provider_label} a rejeté la clé API configurée",
            )
        if error.kind == "timeout":
            raise ServiceUnavailableError(
                code="cti_enrichment_unavailable",
                message=f"La requête vers {provider_label} a expiré",
            )
        if error.kind == "rate_limit":
            raise ServiceUnavailableError(
                code="cti_enrichment_unavailable",
                message=f"La limite de débit de {provider_label} a été atteinte",
            )
        if error.kind == "service_unavailable":
            raise ServiceUnavailableError(
                code="cti_enrichment_unavailable",
                message=f"Le service {provider_label} est indisponible",
            )
        if error.kind == "dns_error":
            raise ServiceUnavailableError(
                code="cti_enrichment_unavailable",
                message=f"La résolution DNS de {provider_label} a échoué",
            )

        raise ServiceUnavailableError(
            code="cti_enrichment_unavailable",
            message=f"{provider_label} a renvoyé une réponse inattendue",
        )
