"""Point d'entree des tests stats."""

from __future__ import annotations

import unittest

from tests.stats import test_routes

TEST_MODULES = (test_routes,)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement les tests stats."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
