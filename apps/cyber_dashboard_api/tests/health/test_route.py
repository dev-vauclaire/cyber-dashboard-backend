"""Tests de la route GET /health."""

from __future__ import annotations

import unittest

from cyber_dashboard_api.api.routes.health import healthcheck

from tests.common import dump_schema


class HealthcheckRouteTestCase(unittest.TestCase):
    """Couvre la route technique de disponibilite."""

    def test_healthcheck_returns_ok_status(self) -> None:
        response = healthcheck()

        self.assertEqual(dump_schema(response), {"status": "ok"})
