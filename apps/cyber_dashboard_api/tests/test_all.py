"""Point d'entree pour lancer toute la suite de tests disponible."""

from __future__ import annotations

import unittest

from tests.attacks_collector_config import test_all as attacks_collector_config_test_all
from tests.attacks import test_all as attacks_test_all
from tests.alerts import test_all as alerts_test_all
from tests.cti_enrichment import test_all as cti_enrichment_test_all
from tests.cti_config import test_all as cti_config_test_all
from tests.dashboard import test_all as dashboard_test_all
from tests.health import test_all as health_test_all
from tests.retention_policies import test_all as retention_policies_test_all
from tests.smtp_config import test_all as smtp_config_test_all
from tests.sources import test_all as sources_test_all
from tests.stats import test_all as stats_test_all
from tests import test_errors

TEST_MODULES = (
    attacks_test_all,
    attacks_collector_config_test_all,
    alerts_test_all,
    cti_enrichment_test_all,
    cti_config_test_all,
    dashboard_test_all,
    health_test_all,
    test_errors,
    retention_policies_test_all,
    smtp_config_test_all,
    sources_test_all,
    stats_test_all,
)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement les suites de tests disponibles."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
