"""Tests unitaires du validateur SMTP."""

from __future__ import annotations

import smtplib
import socket
import unittest
from unittest.mock import Mock, patch

from cyber_dashboard_api.integrations.smtp.types import SmtpValidationContext
from cyber_dashboard_api.integrations.smtp.validator import SmtpValidator


def build_context(*, smtp_port: int = 587) -> SmtpValidationContext:
    """Construit un contexte SMTP minimal valide."""
    return SmtpValidationContext(
        smtp_host="smtp.example.local",
        smtp_port=smtp_port,
        smtp_user="cyber-dashboard@example.local",
        smtp_password="smtp-secret",
        smtp_from="cyber-dashboard@example.local",
        timeout_seconds=5.0,
    )


class SmtpValidatorTestCase(unittest.TestCase):
    """Couvre les scenarii de validation SMTP."""

    def setUp(self) -> None:
        self.validator = SmtpValidator()

    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP")
    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP_SSL")
    def test_port_465_uses_smtp_ssl(
        self,
        smtp_ssl_mock: Mock,
        smtp_mock: Mock,
    ) -> None:
        server = Mock()
        smtp_ssl_mock.return_value = server

        result = self.validator.validate(build_context(smtp_port=465))

        self.assertTrue(result.success)
        smtp_ssl_mock.assert_called_once_with(
            "smtp.example.local",
            465,
            timeout=5.0,
        )
        smtp_mock.assert_not_called()
        server.login.assert_called_once_with(
            "cyber-dashboard@example.local",
            "smtp-secret",
        )
        server.quit.assert_called_once()

    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP")
    def test_port_587_uses_starttls(self, smtp_mock: Mock) -> None:
        server = Mock()
        server.has_extn.return_value = True
        smtp_mock.return_value = server

        result = self.validator.validate(build_context(smtp_port=587))

        self.assertTrue(result.success)
        smtp_mock.assert_called_once_with(
            "smtp.example.local",
            587,
            timeout=5.0,
        )
        self.assertEqual(server.ehlo.call_count, 2)
        server.starttls.assert_called_once_with()
        server.login.assert_called_once_with(
            "cyber-dashboard@example.local",
            "smtp-secret",
        )

    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP")
    def test_port_587_without_starttls_returns_tls_error(self, smtp_mock: Mock) -> None:
        server = Mock()
        server.has_extn.return_value = False
        smtp_mock.return_value = server

        result = self.validator.validate(build_context(smtp_port=587))

        self.assertFalse(result.success)
        self.assertEqual(result.message, "Erreur TLS lors de la validation SMTP.")
        server.login.assert_not_called()

    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP")
    def test_timeout_returns_timeout_message(self, smtp_mock: Mock) -> None:
        smtp_mock.side_effect = socket.timeout()

        result = self.validator.validate(build_context(smtp_port=587))

        self.assertFalse(result.success)
        self.assertEqual(
            result.message,
            "Délai d'attente dépassé lors de la connexion SMTP.",
        )

    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP_SSL")
    def test_auth_failure_returns_auth_message(self, smtp_ssl_mock: Mock) -> None:
        server = Mock()
        server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Auth failed")
        smtp_ssl_mock.return_value = server

        result = self.validator.validate(build_context(smtp_port=465))

        self.assertFalse(result.success)
        self.assertEqual(result.message, "Authentification SMTP refusée.")

    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP_SSL")
    def test_unexpected_response_returns_unexpected_message(
        self,
        smtp_ssl_mock: Mock,
    ) -> None:
        server = Mock()
        server.login.side_effect = smtplib.SMTPResponseException(500, b"Oops")
        smtp_ssl_mock.return_value = server

        result = self.validator.validate(build_context(smtp_port=465))

        self.assertFalse(result.success)
        self.assertEqual(result.message, "Réponse SMTP inattendue.")

    @patch("cyber_dashboard_api.integrations.smtp.validator.smtplib.SMTP")
    def test_other_ports_attempt_starttls_if_announced(self, smtp_mock: Mock) -> None:
        server = Mock()
        server.has_extn.return_value = True
        smtp_mock.return_value = server

        result = self.validator.validate(build_context(smtp_port=2525))

        self.assertTrue(result.success)
        server.starttls.assert_called_once_with()
