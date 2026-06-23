"""Tests unitaires des regles metier SMTP."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.errors import BadRequestError
from cyber_dashboard_api.api.schemas.smtp_config import SmtpConfigUpdateRequestSchema
from cyber_dashboard_api.integrations.common import ValidationResult
from cyber_dashboard_api.services import SmtpConfigService

from tests.smtp_config.helpers import (
    FakeSmtpConfigRepository,
    FakeValidator,
    build_secret_service,
    build_smtp_row,
    build_validation_settings,
)


class SmtpConfigServiceTestCase(unittest.TestCase):
    """Couvre les regles metier de la configuration SMTP."""

    def setUp(self) -> None:
        self.secret_service = build_secret_service()
        self.repository = FakeSmtpConfigRepository(build_smtp_row())
        self.validator = FakeValidator(ValidationResult.ok())
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

    def test_update_encrypts_password_and_returns_hint(self) -> None:
        self.repository.row["is_active"] = True
        self.repository.row["last_validation_status"] = "success"
        payload = SmtpConfigUpdateRequestSchema(smtp_password="super-secret")

        response = self.service.update_config(payload)

        self.assertTrue(response["has_smtp_password"])
        self.assertEqual(response["smtp_password_hint"], "****cret")
        self.assertFalse(response["is_active"])
        self.assertEqual(response["last_validation_status"], "not_tested")
        self.assertNotEqual(
            self.repository.row["encrypted_smtp_password"],
            "super-secret",
        )
        self.assertEqual(
            self.secret_service.decrypt_secret(
                self.repository.row["encrypted_smtp_password"]
            ),
            "super-secret",
        )

    def test_update_without_password_preserves_existing_secret(self) -> None:
        encrypted_password = self.secret_service.encrypt_secret("existing-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
                is_active=True,
                last_validation_status="success",
            )
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )
        payload = SmtpConfigUpdateRequestSchema(smtp_from_name="Cyber Dashboard Ops")

        response = self.service.update_config(payload)

        self.assertEqual(
            self.repository.row["encrypted_smtp_password"],
            encrypted_password,
        )
        self.assertTrue(response["has_smtp_password"])
        self.assertEqual(response["smtp_password_hint"], "****cret")
        self.assertTrue(response["is_active"])
        self.assertEqual(response["last_validation_status"], "success")

    def test_update_rejects_empty_password(self) -> None:
        payload = SmtpConfigUpdateRequestSchema(smtp_password="   ")

        with self.assertRaises(BadRequestError) as context:
            self.service.update_config(payload)

        self.assertEqual(context.exception.code, "invalid_payload")
        self.assertIn("DELETE /api/smtp-config/password", context.exception.message)

    def test_update_rejects_blank_host(self) -> None:
        payload = SmtpConfigUpdateRequestSchema(smtp_host="   ")

        with self.assertRaises(BadRequestError) as context:
            self.service.update_config(payload)

        self.assertEqual(context.exception.code, "invalid_payload")
        self.assertIn("smtp_host", context.exception.message)

    def test_update_rejects_invalid_from_email(self) -> None:
        payload = SmtpConfigUpdateRequestSchema(smtp_from="invalid-email")

        with self.assertRaises(BadRequestError) as context:
            self.service.update_config(payload)

        self.assertEqual(context.exception.code, "invalid_payload")
        self.assertIn("adresse email valide", context.exception.message)

    def test_update_rejects_from_name_header_injection(self) -> None:
        payload = SmtpConfigUpdateRequestSchema(
            smtp_from_name="Cyber Dashboard\nBcc: attacker@example.net"
        )

        with self.assertRaises(BadRequestError) as context:
            self.service.update_config(payload)

        self.assertEqual(context.exception.code, "invalid_payload")

    def test_update_rejects_empty_payload(self) -> None:
        payload = SmtpConfigUpdateRequestSchema()

        with self.assertRaises(BadRequestError) as context:
            self.service.update_config(payload)

        self.assertEqual(context.exception.code, "invalid_payload")

    def test_update_critical_change_resets_activation_and_validation(self) -> None:
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=self.secret_service.encrypt_secret(
                    "existing-secret"
                ),
                smtp_password_hint="****cret",
                is_active=True,
                last_validation_status="success",
                last_validation_error=None,
            )
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )
        payload = SmtpConfigUpdateRequestSchema(smtp_host="smtp-new.example.local")

        response = self.service.update_config(payload)

        self.assertFalse(response["is_active"])
        self.assertEqual(response["last_validation_status"], "not_tested")
        self.assertIsNone(response["last_validation_at"])
        self.assertIsNone(response["last_validation_error"])

    def test_activate_success_sets_configuration_active(self) -> None:
        encrypted_password = self.secret_service.encrypt_secret("smtp-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
            )
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

        response = self.service.activate_config()

        self.assertTrue(response["is_active"])
        self.assertEqual(response["last_validation_status"], "success")
        self.assertIsNone(response["last_validation_error"])
        self.assertEqual(self.validator.last_context.smtp_password, "smtp-secret")

    def test_activate_incomplete_configuration_returns_bad_request(self) -> None:
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                smtp_user=None,
                encrypted_smtp_password=None,
                smtp_password_hint=None,
            )
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

        with self.assertRaises(BadRequestError) as context:
            self.service.activate_config()

        self.assertEqual(context.exception.code, "smtp_validation_failed")
        self.assertEqual(context.exception.message, "Configuration SMTP incomplète.")
        self.assertFalse(self.repository.row["is_active"])
        self.assertEqual(self.repository.row["last_validation_status"], "failed")
        self.assertEqual(
            self.repository.row["last_validation_error"],
            "Configuration SMTP incomplète.",
        )
        self.assertIsNotNone(self.repository.row["last_validation_at"])

    def test_activate_auth_failure_returns_bad_request(self) -> None:
        encrypted_password = self.secret_service.encrypt_secret("smtp-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
            )
        )
        self.validator = FakeValidator(
            ValidationResult.fail("Authentification SMTP refusée.")
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

        with self.assertRaises(BadRequestError) as context:
            self.service.activate_config()

        self.assertEqual(context.exception.code, "smtp_validation_failed")
        self.assertEqual(
            self.repository.row["last_validation_error"],
            "Authentification SMTP refusée.",
        )
        self.assertFalse(self.repository.row["is_active"])

    def test_test_failure_preserves_active_status(self) -> None:
        encrypted_password = self.secret_service.encrypt_secret("smtp-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
                is_active=True,
                last_validation_status="success",
            )
        )
        self.validator = FakeValidator(
            ValidationResult.fail("Authentification SMTP refusée.")
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

        with self.assertRaises(BadRequestError):
            self.service.test_config()

        self.assertTrue(self.repository.row["is_active"])
        self.assertEqual(self.repository.row["last_validation_status"], "failed")

    def test_activate_timeout_returns_bad_request(self) -> None:
        encrypted_password = self.secret_service.encrypt_secret("smtp-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
            )
        )
        self.validator = FakeValidator(
            ValidationResult.fail("Timeout lors de la connexion SMTP.")
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

        with self.assertRaises(BadRequestError) as context:
            self.service.activate_config()

        self.assertEqual(context.exception.code, "smtp_validation_failed")
        self.assertEqual(
            self.repository.row["last_validation_error"],
            "Timeout lors de la connexion SMTP.",
        )
        self.assertFalse(self.repository.row["is_active"])

    def test_deactivate_preserves_encrypted_password(self) -> None:
        encrypted_password = self.secret_service.encrypt_secret("smtp-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
                is_active=True,
                last_validation_status="success",
            )
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

        response = self.service.deactivate_config()

        self.assertFalse(response["is_active"])
        self.assertEqual(
            self.repository.row["encrypted_smtp_password"],
            encrypted_password,
        )
        self.assertEqual(self.repository.row["smtp_password_hint"], "****cret")
        self.assertEqual(self.repository.row["last_validation_status"], "success")

    def test_delete_password_clears_secret_and_resets_validation(self) -> None:
        encrypted_password = self.secret_service.encrypt_secret("smtp-secret")
        self.repository = FakeSmtpConfigRepository(
            build_smtp_row(
                encrypted_smtp_password=encrypted_password,
                smtp_password_hint="****cret",
                is_active=True,
                last_validation_status="success",
            )
        )
        self.service = SmtpConfigService(
            self.repository,
            self.secret_service,
            self.validator,
            build_validation_settings(),
        )

        response = self.service.delete_password()

        self.assertFalse(response["has_smtp_password"])
        self.assertIsNone(self.repository.row["encrypted_smtp_password"])
        self.assertIsNone(self.repository.row["smtp_password_hint"])
        self.assertFalse(self.repository.row["is_active"])
        self.assertEqual(self.repository.row["last_validation_status"], "not_tested")
        self.assertIsNone(self.repository.row["last_validation_at"])
        self.assertIsNone(self.repository.row["last_validation_error"])
