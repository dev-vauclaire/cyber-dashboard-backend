"""Registry des validateurs CTI."""

from __future__ import annotations

from cyber_dashboard_api.config import ValidationSettings
from cyber_dashboard_api.integrations.cti.clients.abuseipdb_client import AbuseIpdbClient
from cyber_dashboard_api.integrations.cti.clients.greynoise_client import GreyNoiseClient
from cyber_dashboard_api.integrations.cti.clients.ipdata_client import IpDataClient
from cyber_dashboard_api.integrations.cti.clients.shodan_client import ShodanClient
from cyber_dashboard_api.integrations.cti.clients.virustotal_client import VirusTotalClient
from cyber_dashboard_api.integrations.cti.validators.abuseipdb_validator import (
    AbuseIpdbValidator,
)
from cyber_dashboard_api.integrations.cti.validators.greynoise_validator import (
    GreyNoiseValidator,
)
from cyber_dashboard_api.integrations.cti.validators.ipdata_validator import (
    IpDataValidator,
)
from cyber_dashboard_api.integrations.cti.validators.shodan_validator import (
    ShodanValidator,
)
from cyber_dashboard_api.integrations.cti.validators.virustotal_validator import (
    VirusTotalValidator,
)


class CtiValidatorRegistry:
    """Expose les validateurs CTI par code provider."""

    def __init__(self, settings: ValidationSettings) -> None:
        timeout = settings.timeout_seconds
        self._validators = {
            "abuseipdb": AbuseIpdbValidator(AbuseIpdbClient(timeout_seconds=timeout)),
            "ipdata": IpDataValidator(IpDataClient(timeout_seconds=timeout)),
            "greynoise": GreyNoiseValidator(GreyNoiseClient(timeout_seconds=timeout)),
            "virustotal": VirusTotalValidator(
                VirusTotalClient(timeout_seconds=timeout)
            ),
            "shodan": ShodanValidator(ShodanClient(timeout_seconds=timeout)),
        }

    def get_validator(self, code: str):
        """Retourne le validateur correspondant au code demandé."""
        return self._validators.get(code)
