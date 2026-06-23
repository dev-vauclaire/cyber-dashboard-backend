"""Tests du middleware de delai de reponse en developpement."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase, mock

from cyber_dashboard_api.config.settings import (
    DatabaseSettings,
    SecretSettings,
    Settings,
    ValidationSettings,
)
from cyber_dashboard_api.main import (
    _build_dev_response_delay_middleware,
    _matches_dev_delay_path,
)


def build_settings(
    *,
    delay_seconds: float,
    delay_paths: tuple[str, ...] = (),
) -> Settings:
    """Construit des settings minimaux pour les tests de middleware."""
    return Settings(
        api_name="Cyber Dashboard API",
        api_host="127.0.0.1",
        api_port=8000,
        api_log_level="INFO",
        api_dev_response_delay_seconds=delay_seconds,
        api_dev_response_delay_paths=delay_paths,
        database=DatabaseSettings(
            host="localhost",
            port=5432,
            name="cyber_dashboard",
            user="postgres",
            password="postgres",
        ),
        secrets=SecretSettings(
            secret_key_file=None,
            secret_key=None,
        ),
        validation=ValidationSettings(
            timeout_seconds=5.0,
            test_ip="8.8.8.8",
            ogo_base_url=None,
            serenicity_base_url=None,
        ),
    )


class DevDelayMiddlewarePathMatchingTestCase(TestCase):
    """Verifie le filtrage de chemins du delai."""

    def test_matches_all_routes_when_no_path_filter_is_defined(self) -> None:
        self.assertTrue(_matches_dev_delay_path("/health", ()))

    def test_matches_path_prefix_when_filter_is_defined(self) -> None:
        self.assertTrue(
            _matches_dev_delay_path("/api/attacks?page=1", ("/api/attacks",))
        )

    def test_does_not_match_non_selected_prefix(self) -> None:
        self.assertFalse(
            _matches_dev_delay_path("/health", ("/api/attacks", "/api/stats"))
        )


class DevDelayMiddlewareTestCase(IsolatedAsyncioTestCase):
    """Verifie l'application du delai HTTP de developpement."""

    @staticmethod
    def _build_request(path: str) -> SimpleNamespace:
        return SimpleNamespace(url=SimpleNamespace(path=path))

    async def test_delay_is_applied_to_all_routes_when_no_path_filter_is_defined(
        self,
    ) -> None:
        settings = build_settings(delay_seconds=0.25)
        middleware = _build_dev_response_delay_middleware(settings)
        call_next = mock.AsyncMock(return_value="ok")

        with mock.patch(
            "cyber_dashboard_api.main.asyncio.sleep",
            new_callable=mock.AsyncMock,
        ) as sleep_mock:
            response = await middleware(self._build_request("/health"), call_next)

        self.assertEqual(response, "ok")
        sleep_mock.assert_awaited_once_with(0.25)
        call_next.assert_awaited_once()

    async def test_delay_is_skipped_when_path_filter_does_not_match(self) -> None:
        settings = build_settings(
            delay_seconds=0.25,
            delay_paths=("/api/attacks", "/api/stats"),
        )
        middleware = _build_dev_response_delay_middleware(settings)
        call_next = mock.AsyncMock(return_value="ok")

        with mock.patch(
            "cyber_dashboard_api.main.asyncio.sleep",
            new_callable=mock.AsyncMock,
        ) as sleep_mock:
            response = await middleware(self._build_request("/health"), call_next)

        self.assertEqual(response, "ok")
        sleep_mock.assert_not_awaited()
        call_next.assert_awaited_once()

    async def test_delay_is_applied_when_path_filter_matches(self) -> None:
        settings = build_settings(
            delay_seconds=0.25,
            delay_paths=("/health",),
        )
        middleware = _build_dev_response_delay_middleware(settings)
        call_next = mock.AsyncMock(return_value="ok")

        with mock.patch(
            "cyber_dashboard_api.main.asyncio.sleep",
            new_callable=mock.AsyncMock,
        ) as sleep_mock:
            response = await middleware(self._build_request("/health"), call_next)

        self.assertEqual(response, "ok")
        sleep_mock.assert_awaited_once_with(0.25)
        call_next.assert_awaited_once()
