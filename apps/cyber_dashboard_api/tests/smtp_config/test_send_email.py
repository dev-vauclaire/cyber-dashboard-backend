"""Tests de l'envoi generique via la configuration SMTP."""

from __future__ import annotations

import smtplib
import unittest
from unittest.mock import MagicMock, patch

from cyber_dashboard_api.api.errors import BadRequestError, ServiceUnavailableError
from cyber_dashboard_api.api.routes.smtp_config import send_smtp_email
from cyber_dashboard_api.api.schemas import SmtpEmailRequestSchema
from cyber_dashboard_api.services import SmtpEmailService

from tests.smtp_config.helpers import (
    FakeSmtpConfigRepository,
    build_secret_service,
    build_smtp_row,
    build_validation_settings,
    dump_schema,
)


class FakeSmtpEmailService:
    """Service fake pour couvrir la route d'envoi."""

    def __init__(self) -> None:
        self.payload: object | None = None

    def send_email(self, *, payload: object) -> dict[str, object]:
        self.payload = payload
        return {"recipient": "ops@example.net", "sent": True}


class SendSmtpEmailRouteTestCase(unittest.TestCase):
    """Couvre POST /api/smtp-config/send-email."""

    def test_route_delegates_to_email_service(self) -> None:
        service = FakeSmtpEmailService()
        payload = SmtpEmailRequestSchema(
            recipient="ops@example.net",
            subject="Alerte automatique",
            body="Une alerte a été détectée.",
        )

        response = send_smtp_email(payload=payload, smtp_email_service=service)

        body = dump_schema(response)
        self.assertTrue(body["sent"])
        self.assertEqual(body["recipient"], "ops@example.net")
        self.assertIs(service.payload, payload)


class SmtpEmailServiceTestCase(unittest.TestCase):
    """Couvre les regles et le transport de l'envoi SMTP."""

    def setUp(self) -> None:
        self.secret_service = build_secret_service()
        encrypted_password = self.secret_service.encrypt_secret("smtp-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
                is_active=True,
                last_validation_status="success",
            )
        )
        self.service = SmtpEmailService(
            self.repository,
            self.secret_service,
            build_validation_settings(),
        )
        self.payload = SmtpEmailRequestSchema(
            recipient="ops@example.net",
            subject="  Alerte automatique  ",
            body="  Une alerte a été détectée.  ",
        )

    def test_inactive_configuration_is_rejected(self) -> None:
        self.repository.row["is_active"] = False

        with self.assertRaises(BadRequestError) as context:
            self.service.send_email(payload=self.payload)

        self.assertEqual(context.exception.code, "smtp_config_inactive")

    def test_incomplete_configuration_is_rejected(self) -> None:
        self.repository.row["smtp_from"] = None

        with self.assertRaises(BadRequestError) as context:
            self.service.send_email(payload=self.payload)

        self.assertEqual(context.exception.code, "smtp_config_incomplete")

    def test_subject_header_injection_is_rejected(self) -> None:
        payload = SmtpEmailRequestSchema(
            recipient="ops@example.net",
            subject="Alerte\nBcc: attacker@example.net",
            body="Une alerte a été détectée.",
        )

        with self.assertRaises(BadRequestError) as context:
            self.service.send_email(payload=payload)

        self.assertEqual(context.exception.code, "invalid_payload")

    @patch("cyber_dashboard_api.services.smtp_email_service.ssl.create_default_context")
    @patch("cyber_dashboard_api.services.smtp_email_service.smtplib.SMTP")
    def test_port_587_uses_starttls_and_sends_message(
        self,
        smtp_mock: MagicMock,
        create_context_mock: MagicMock,
    ) -> None:
        server = MagicMock()
        server.has_extn.return_value = True
        smtp_mock.return_value.__enter__.return_value = server
        tls_context = object()
        create_context_mock.return_value = tls_context

        result = self.service.send_email(payload=self.payload)

        self.assertTrue(result["sent"])
        smtp_mock.assert_called_once_with("smtp.example.local", 587, timeout=5.0)
        server.starttls.assert_called_once_with(context=tls_context)
        server.login.assert_called_once_with(
            "cyber-dashboard@example.local",
            "smtp-secret",
        )
        sent_message = server.send_message.call_args.args[0]
        self.assertEqual(sent_message["To"], "ops@example.net")
        self.assertEqual(sent_message["Subject"], "Alerte automatique")
        self.assertEqual(
            sent_message["From"],
            "Cyber Dashboard <cyber-dashboard@example.local>",
        )
        self.assertEqual(
            sent_message.get_content().strip(), "Une alerte a été détectée."
        )

    @patch("cyber_dashboard_api.services.smtp_email_service.smtplib.SMTP_SSL")
    def test_port_465_uses_implicit_tls(self, smtp_ssl_mock: MagicMock) -> None:
        self.repository.row["smtp_port"] = 465
        server = MagicMock()
        smtp_ssl_mock.return_value.__enter__.return_value = server

        self.service.send_email(payload=self.payload)

        smtp_ssl_mock.assert_called_once_with("smtp.example.local", 465, timeout=5.0)
        server.send_message.assert_called_once()

    @patch("cyber_dashboard_api.services.smtp_email_service.smtplib.SMTP")
    def test_smtp_failure_is_normalized(self, smtp_mock: MagicMock) -> None:
        smtp_mock.side_effect = smtplib.SMTPConnectError(421, b"unavailable")

        with self.assertRaises(ServiceUnavailableError) as context:
            self.service.send_email(payload=self.payload)

        self.assertEqual(context.exception.code, "smtp_send_failed")
