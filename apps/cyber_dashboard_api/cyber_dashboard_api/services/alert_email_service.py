"""Service metier pour l'envoi manuel d'emails d'alerte."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from cyber_dashboard_api.api.errors import (
    BadRequestError,
    NotFoundError,
    ServiceUnavailableError,
)
from cyber_dashboard_api.api.validation import validate_email_input
from cyber_dashboard_api.config import ValidationSettings
from cyber_dashboard_api.repositories import AlertRepository, SmtpConfigRepository
from cyber_dashboard_api.services.secret_service import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretService,
)


class AlertEmailService:
    """Envoie un email manuel pour une alerte IP commune."""

    def __init__(
        self,
        alert_repository: AlertRepository,
        smtp_config_repository: SmtpConfigRepository,
        secret_service: SecretService,
        validation_settings: ValidationSettings,
    ) -> None:
        self._alert_repository = alert_repository
        self._smtp_config_repository = smtp_config_repository
        self._secret_service = secret_service
        self._validation_settings = validation_settings

    def send_alert_email(self, *, alert_id: int, payload: Any) -> dict[str, Any]:
        """Envoie un email manuel rattache a une alerte existante."""
        alert_rows = self._alert_repository.get_alert_detail_by_alert_id(alert_id)
        if not alert_rows:
            raise NotFoundError(
                code="common_ip_alert_not_found",
                message="Common IP alert not found",
            )

        recipient = validate_email_input(
            name="recipient",
            value=payload.recipient,
            max_length=255,
        )
        subject = self._normalize_non_blank_text(
            name="subject",
            value=payload.subject,
            max_length=255,
        )
        body = self._normalize_non_blank_text(
            name="body",
            value=payload.body,
            max_length=10000,
        )

        smtp_row = self._smtp_config_repository.get_or_create_config()
        if not smtp_row["is_active"]:
            raise BadRequestError(
                code="smtp_config_inactive",
                message="SMTP configuration must be active before sending alert emails",
            )

        self._send_email(
            smtp_row=smtp_row,
            recipient=recipient,
            subject=subject,
            body=body,
        )
        return {
            "alert_id": alert_id,
            "recipient": recipient,
            "sent": True,
        }

    def _send_email(
        self,
        *,
        smtp_row: dict[str, Any],
        recipient: str,
        subject: str,
        body: str,
    ) -> None:
        missing_fields = [
            field_name
            for field_name in ("smtp_host", "smtp_port", "smtp_user", "smtp_from")
            if smtp_row.get(field_name) in (None, "")
        ]
        if not self._secret_service.has_secret(smtp_row.get("encrypted_smtp_password")):
            missing_fields.append("smtp_password")

        if missing_fields:
            raise BadRequestError(
                code="smtp_config_incomplete",
                message="SMTP configuration is incomplete",
            )

        password = self._decrypt_secret(smtp_row["encrypted_smtp_password"])
        message = EmailMessage()
        message["From"] = self._format_sender(
            smtp_from=smtp_row["smtp_from"],
            smtp_from_name=smtp_row.get("smtp_from_name"),
        )
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)

        try:
            if int(smtp_row["smtp_port"]) == 465:
                with smtplib.SMTP_SSL(
                    smtp_row["smtp_host"],
                    int(smtp_row["smtp_port"]),
                    timeout=self._validation_settings.timeout_seconds,
                ) as server:
                    server.login(smtp_row["smtp_user"], password)
                    server.send_message(message)
                return

            with smtplib.SMTP(
                smtp_row["smtp_host"],
                int(smtp_row["smtp_port"]),
                timeout=self._validation_settings.timeout_seconds,
            ) as server:
                if int(smtp_row["smtp_port"]) == 587:
                    server.starttls(context=ssl.create_default_context())
                server.login(smtp_row["smtp_user"], password)
                server.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise ServiceUnavailableError(
                code="smtp_send_failed",
                message="Unable to send alert email with the current SMTP configuration",
            ) from exc

    def _decrypt_secret(self, encrypted_value: str) -> str:
        try:
            return self._secret_service.decrypt_secret(encrypted_value)
        except (SecretConfigurationError, SecretDecryptionError) as exc:
            raise ServiceUnavailableError(
                code="secret_key_unavailable",
                message="Stored SMTP password could not be decrypted",
            ) from exc

    @staticmethod
    def _format_sender(*, smtp_from: str, smtp_from_name: str | None) -> str:
        if smtp_from_name is None or smtp_from_name.strip() == "":
            return smtp_from
        return f"{smtp_from_name} <{smtp_from}>"

    @staticmethod
    def _normalize_non_blank_text(
        *,
        name: str,
        value: str,
        max_length: int,
    ) -> str:
        normalized = value.strip()
        if normalized == "":
            raise BadRequestError(
                code="invalid_payload",
                message=f"Field '{name}' must not be blank",
            )
        if len(normalized) > max_length:
            raise BadRequestError(
                code="invalid_payload",
                message=f"Field '{name}' must contain at most {max_length} characters",
            )
        return normalized
