"""Socle partagé des clients de collecteurs."""

from cyber_dashboard_api.integrations.common import IntegrationRequestError
from cyber_dashboard_api.integrations.http import HttpJsonClient

__all__ = ["HttpJsonClient", "IntegrationRequestError"]
