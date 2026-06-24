"""Service metier pour l'envoi manuel d'emails d'alerte."""

from __future__ import annotations

from typing import Any

from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.repositories import AlertRepository
from cyber_dashboard_api.services.smtp_email_service import SmtpEmailService


class AlertEmailService:
    """Envoie un email manuel pour une alerte IP commune."""

    def __init__(
        self,
        alert_repository: AlertRepository,
        smtp_email_service: SmtpEmailService,
    ) -> None:
        self._alert_repository = alert_repository
        self._smtp_email_service = smtp_email_service

    def send_alert_email(self, *, alert_id: int, payload: Any) -> dict[str, Any]:
        """Envoie un email manuel rattache a une alerte existante."""
        alert_rows = self._alert_repository.get_alert_detail_by_alert_id(alert_id)
        if not alert_rows:
            raise NotFoundError(
                code="common_ip_alert_not_found",
                message="Alerte IP commune introuvable",
            )

        result = self._smtp_email_service.send_email(payload=payload)
        return {
            "alert_id": alert_id,
            "recipient": result["recipient"],
            "sent": result["sent"],
        }
