"""Point d'entree des tests health."""

from __future__ import annotations

import unittest

from tests.health import test_dev_delay_middleware, test_route


TEST_MODULES = (test_route, test_dev_delay_middleware)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement les tests health."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
