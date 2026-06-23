"""Point d'entree des tests CTI."""

from __future__ import annotations

import unittest

from tests.cti_config import (
    test_greynoise_validator,
    test_routes,
    test_service,
    test_shodan_validator,
)

TEST_MODULES = (
    test_greynoise_validator,
    test_shodan_validator,
    test_routes,
    test_service,
)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement les tests CTI."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
