"""Point d'entree des tests attaques."""

from __future__ import annotations

import unittest

from tests.attacks import test_route

TEST_MODULES = (test_route,)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement les tests attaques."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
