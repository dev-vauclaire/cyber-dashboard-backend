"""Smoke tests du package scheduler."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from cyber_dashboard_scheduler.config import ConfigurationError, Settings
from cyber_dashboard_scheduler.config.settings import ENV_FILE_PATH
from cyber_dashboard_scheduler.main import main


class SchedulerSmokeTests(unittest.TestCase):
    """Verifie que le scheduler est importable et configurable sans service externe."""

    def test_env_file_path_targets_application_root(self) -> None:
        expected_path = Path(__file__).resolve().parents[1] / ".env"

        self.assertEqual(ENV_FILE_PATH, expected_path)

    def test_settings_can_be_built_from_environment(self) -> None:
        environment = {
            "DB_HOST": "localhost",
            "DB_PORT": "5432",
            "DB_NAME": "cyber_dashboard_test",
            "DB_USER": "cyber_dashboard_test",
            "DB_PASSWORD": "test-password",
            "LIMIT_REQUEST_PER_DAY": "24",
            "LOG_LEVEL": "INFO",
            "OGO_BASE_URL": "https://ogo.example.test",
            "SERENICITY_BASE_URL": "https://serenicity.example.test",
        }

        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch("cyber_dashboard_scheduler.config.settings._load_env_file"),
        ):
            settings = Settings.from_env()

        self.assertEqual(settings.database.host, "localhost")
        self.assertEqual(settings.database.port, 5432)
        self.assertEqual(settings.limit_request_per_day, 24)
        self.assertEqual(settings.log_level, "INFO")

    def test_main_returns_failure_for_invalid_configuration(self) -> None:
        configuration_error = ConfigurationError("configuration absente")

        with (
            mock.patch.object(
                Settings,
                "from_env",
                side_effect=configuration_error,
            ),
            mock.patch("cyber_dashboard_scheduler.main.configure_logging"),
            mock.patch("cyber_dashboard_scheduler.main.LOGGER") as logger,
        ):
            exit_code = main()

        self.assertEqual(exit_code, 1)
        logger.error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
