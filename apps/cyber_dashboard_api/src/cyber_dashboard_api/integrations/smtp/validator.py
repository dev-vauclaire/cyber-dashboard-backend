"""Validateur SMTP réel via connexion et authentification."""

from __future__ import annotations

import smtplib
import socket
import ssl

from cyber_dashboard_api.integrations.common import ValidationResult
from cyber_dashboard_api.integrations.smtp.types import SmtpValidationContext


class _SmtpTlsValidationError(RuntimeError):
    """Erreur interne pour normaliser les echecs STARTTLS."""


class SmtpValidator:
    """Teste une connexion SMTP et l'authentification sans envoyer d'email."""

    def validate(self, context: SmtpValidationContext) -> ValidationResult:
        server: smtplib.SMTP | smtplib.SMTP_SSL | None = None
        try:
            if context.smtp_port == 465:
                server = smtplib.SMTP_SSL(
                    context.smtp_host,
                    context.smtp_port,
                    timeout=context.timeout_seconds,
                )
                server.login(context.smtp_user, context.smtp_password)
                return ValidationResult.ok(provider_status_code=200)

            server = smtplib.SMTP(
                context.smtp_host,
                context.smtp_port,
                timeout=context.timeout_seconds,
            )
            server.ehlo()

            if context.smtp_port == 587:
                self._starttls_required(server)
            else:
                self._starttls_if_available(server)

            server.login(context.smtp_user, context.smtp_password)
            return ValidationResult.ok(provider_status_code=200)
        except smtplib.SMTPAuthenticationError as exc:
            return ValidationResult.fail(
                "Authentification SMTP refusée.",
                provider_status_code=exc.smtp_code,
            )
        except (socket.timeout, TimeoutError):
            return ValidationResult.fail("Timeout lors de la connexion SMTP.")
        except (_SmtpTlsValidationError, ssl.SSLError, smtplib.SMTPNotSupportedError):
            return ValidationResult.fail("Erreur TLS lors de la validation SMTP.")
        except smtplib.SMTPConnectError as exc:
            return ValidationResult.fail(
                "Impossible de se connecter au serveur SMTP.",
                provider_status_code=exc.smtp_code,
            )
        except (
            smtplib.SMTPServerDisconnected,
            smtplib.SMTPHeloError,
            smtplib.SMTPResponseException,
            smtplib.SMTPException,
        ) as exc:
            provider_status_code = getattr(exc, "smtp_code", None)
            return ValidationResult.fail(
                "Réponse SMTP inattendue.",
                provider_status_code=provider_status_code,
            )
        except (socket.gaierror, ConnectionError, OSError):
            return ValidationResult.fail("Impossible de se connecter au serveur SMTP.")
        finally:
            if server is not None:
                try:
                    server.quit()
                except (OSError, smtplib.SMTPException):
                    pass

    @staticmethod
    def _starttls_required(server: smtplib.SMTP) -> None:
        """Active STARTTLS et echoue explicitement si le serveur ne le supporte pas."""
        if not server.has_extn("starttls"):
            raise _SmtpTlsValidationError("STARTTLS est requis sur le port 587")

        SmtpValidator._starttls(server)

    @staticmethod
    def _starttls_if_available(server: smtplib.SMTP) -> None:
        """Active STARTTLS uniquement si le serveur l'annonce."""
        if server.has_extn("starttls"):
            SmtpValidator._starttls(server)

    @staticmethod
    def _starttls(server: smtplib.SMTP) -> None:
        """Isole la negociation TLS pour la remapper proprement."""
        try:
            server.starttls()
            server.ehlo()
        except (
            ssl.SSLError,
            smtplib.SMTPNotSupportedError,
            smtplib.SMTPResponseException,
            smtplib.SMTPServerDisconnected,
        ) as exc:
            raise _SmtpTlsValidationError("L'activation de STARTTLS a échoué") from exc
