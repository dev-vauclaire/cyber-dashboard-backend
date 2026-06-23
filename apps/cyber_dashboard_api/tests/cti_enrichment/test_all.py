"""Point d'entree des tests d'enrichissement CTI."""

from __future__ import annotations

import unittest

from tests.cti_enrichment import (
    test_abuseipdb_route,
    test_greynoise_route,
    test_ipdata_route,
    test_rdap_route,
    test_shodan_route,
    test_service,
    test_virustotal_route,
)

TEST_MODULES = (
    test_abuseipdb_route,
    test_greynoise_route,
    test_ipdata_route,
    test_rdap_route,
    test_shodan_route,
    test_service,
    test_virustotal_route,
)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement les tests d'enrichissement CTI."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
