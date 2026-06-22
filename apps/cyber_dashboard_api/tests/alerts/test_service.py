"""Tests du service d'envoi des emails d'alerte."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.errors import NotFoundError
from cyber_dashboard_api.api.schemas import AlertEmailRequestSchema
from cyber_dashboard_api.services import AlertEmailService


class FakeAlertRepository:
    """Repository fake pour piloter l'existence d'une alerte."""

    def __init__(self, *, exists: bool) -> None:
        self.exists = exists

    def get_alert_detail_by_alert_id(self, alert_id: int) -> list[dict[str, int]]:
        return [{"id": alert_id}] if self.exists else []


class FakeSmtpEmailService:
    """Service SMTP fake pour verifier la delegation."""

    def __init__(self) -> None:
        self.payload: object | None = None

    def send_email(self, *, payload: object) -> dict[str, object]:
        self.payload = payload
        return {"recipient": "ops@example.net", "sent": True}


class AlertEmailServiceTestCase(unittest.TestCase):
    """Couvre l'adaptation alerte vers l'envoi SMTP generique."""

    def setUp(self) -> None:
        self.smtp_service = FakeSmtpEmailService()
        self.payload = AlertEmailRequestSchema(
            recipient="ops@example.net",
            subject="Alerte IP commune",
            body="Une adresse IP est présente dans plusieurs sources.",
        )

    def test_existing_alert_delegates_to_smtp_service(self) -> None:
        service = AlertEmailService(
            FakeAlertRepository(exists=True),
            self.smtp_service,
        )

        result = service.send_alert_email(alert_id=8, payload=self.payload)

        self.assertEqual(result["alert_id"], 8)
        self.assertTrue(result["sent"])
        self.assertIs(self.smtp_service.payload, self.payload)

    def test_missing_alert_does_not_send_email(self) -> None:
        service = AlertEmailService(
            FakeAlertRepository(exists=False),
            self.smtp_service,
        )

        with self.assertRaises(NotFoundError):
            service.send_alert_email(alert_id=404, payload=self.payload)

        self.assertIsNone(self.smtp_service.payload)
