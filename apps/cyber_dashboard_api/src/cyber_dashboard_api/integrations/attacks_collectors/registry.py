"""Registry des validateurs de collecteurs d'attaques."""

from __future__ import annotations

from cyber_dashboard_api.config import ValidationSettings
from cyber_dashboard_api.integrations.attacks_collectors.clients.ogo_client import (
    OgoClient,
)
from cyber_dashboard_api.integrations.attacks_collectors.clients.serenicity_client import (
    SerenicityClient,
)
from cyber_dashboard_api.integrations.attacks_collectors.validators.ogo_validator import (
    OgoValidator,
)
from cyber_dashboard_api.integrations.attacks_collectors.validators.serenicity_validator import (
    SerenicityValidator,
)


class AttacksCollectorValidatorRegistry:
    """Expose les validateurs des collecteurs par type."""

    def __init__(self, settings: ValidationSettings) -> None:
        timeout = settings.timeout_seconds
        self._validators = {}
        if settings.ogo_base_url:
            self._validators["ogo"] = OgoValidator(
                OgoClient(
                    base_url=settings.ogo_base_url,
                    timeout_seconds=timeout,
                )
            )
        if settings.serenicity_base_url:
            self._validators["serenicity"] = SerenicityValidator(
                SerenicityClient(
                    base_url=settings.serenicity_base_url,
                    timeout_seconds=timeout,
                )
            )

    def get_validator(self, collector_type: str):
        """Retourne le validateur associé au type demandé."""
        return self._validators.get(collector_type)
