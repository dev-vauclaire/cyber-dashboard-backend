"""Service metier generique d'envoi d'emails via la configuration SMTP."""

from __future__ import annotations

import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any

from cyber_dashboard_api.api.errors import BadRequestError, ServiceUnavailableError
from cyber_dashboard_api.api.validation import validate_email_input
from cyber_dashboard_api.config import ValidationSettings
from cyber_dashboard_api.repositories import SmtpConfigRepository
from cyber_dashboard_api.services.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)


class SmtpEmailService:
    """Construit et envoie des emails avec la configuration SMTP active."""

    def __init__(
        self,
        smtp_config_repository: SmtpConfigRepository,
        secret_service: SecretService,
        validation_settings: ValidationSettings,
    ) -> None:
        self._smtp_config_repository = smtp_config_repository
        self._secret_service = secret_service
        self._validation_settings = validation_settings

    def send_email(self, *, payload: Any) -> dict[str, Any]:
        """Valide le message puis l'envoie avec la configuration active."""
        recipient = validate_email_input(
            name="recipient",
            value=payload.recipient,
            max_length=255,
        )
        subject = self._normalize_non_blank_text(
            name="subject",
            value=payload.subject,
            max_length=255,
            single_line=True,
        )
        body = self._normalize_non_blank_text(
            name="body",
            value=payload.body,
            max_length=10000,
        )

        smtp_row = self._smtp_config_repository.get_or_create_config()
        self._validate_active_config(smtp_row)
        password = self._decrypt_secret(smtp_row["encrypted_smtp_password"])
        message = self._build_message(
            smtp_row=smtp_row,
            recipient=recipient,
            subject=subject,
            body=body,
        )
        self._send_message(smtp_row=smtp_row, password=password, message=message)

        return {"recipient": recipient, "sent": True}

    def _validate_active_config(self, smtp_row: dict[str, Any]) -> None:
        if not bool(smtp_row.get("is_active")):
            raise BadRequestError(
                code="smtp_config_inactive",
                message="La configuration SMTP doit être active avant l'envoi d'un e-mail",
            )

        missing_fields = [
            field_name
            for field_name in ("smtp_host", "smtp_port", "smtp_user", "smtp_from")
            if smtp_row.get(field_name) is None
            or (
                isinstance(smtp_row.get(field_name), str)
                and not str(smtp_row[field_name]).strip()
            )
        ]
        if not self._secret_service.has_secret(smtp_row.get("encrypted_smtp_password")):
            missing_fields.append("smtp_password")

        if missing_fields:
            raise BadRequestError(
                code="smtp_config_incomplete",
                message="La configuration SMTP est incomplète",
            )

    def _send_message(
        self,
        *,
        smtp_row: dict[str, Any],
        password: str,
        message: EmailMessage,
    ) -> None:
        host = str(smtp_row["smtp_host"])
        port = int(smtp_row["smtp_port"])
        user = str(smtp_row["smtp_user"])
        timeout = self._validation_settings.timeout_seconds

        try:
            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=timeout) as server:
                    server.login(user, password)
                    server.send_message(message)
                return

            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo()
                if port == 587:
                    if not server.has_extn("starttls"):
                        raise smtplib.SMTPNotSupportedError(
                            "STARTTLS est requis sur le port 587"
                        )
                    self._starttls(server)
                elif server.has_extn("starttls"):
                    self._starttls(server)

                server.login(user, password)
                server.send_message(message)
        except (socket.timeout, TimeoutError, OSError, smtplib.SMTPException) as exc:
            raise ServiceUnavailableError(
                code="smtp_send_failed",
                message="Impossible d'envoyer l'e-mail avec la configuration SMTP actuelle",
            ) from exc

    @staticmethod
    def _starttls(server: smtplib.SMTP) -> None:
        server.starttls(context=ssl.create_default_context())
        server.ehlo()

    @staticmethod
    def _build_message(
        *,
        smtp_row: dict[str, Any],
        recipient: str,
        subject: str,
        body: str,
    ) -> EmailMessage:
        message = EmailMessage()
        message["From"] = SmtpEmailService._format_sender(
            smtp_from=str(smtp_row["smtp_from"]),
            smtp_from_name=smtp_row.get("smtp_from_name"),
        )
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)
        return message

    def _decrypt_secret(self, encrypted_value: str) -> str:
        try:
            return self._secret_service.decrypt_secret(encrypted_value)
        except (SecretConfigurationError, SecretDecryptionError) as exc:
            raise ServiceUnavailableError(
                code="secret_key_unavailable",
                message="Le mot de passe SMTP stocké n'a pas pu être déchiffré",
            ) from exc

    @staticmethod
    def _format_sender(*, smtp_from: str, smtp_from_name: str | None) -> str:
        if smtp_from_name is None or smtp_from_name.strip() == "":
            return smtp_from
        return formataddr((smtp_from_name, smtp_from))

    @staticmethod
    def _normalize_non_blank_text(
        *,
        name: str,
        value: str,
        max_length: int,
        single_line: bool = False,
    ) -> str:
        normalized = value.strip()
        if normalized == "":
            raise BadRequestError(
                code="invalid_payload",
                message=f"Le champ '{name}' ne doit pas être vide",
            )
        if len(normalized) > max_length:
            raise BadRequestError(
                code="invalid_payload",
                message=f"Le champ '{name}' doit contenir au maximum {max_length} caractères",
            )
        if single_line and ("\r" in normalized or "\n" in normalized):
            raise BadRequestError(
                code="invalid_payload",
                message=f"Le champ '{name}' doit tenir sur une seule ligne",
            )
        return normalized
