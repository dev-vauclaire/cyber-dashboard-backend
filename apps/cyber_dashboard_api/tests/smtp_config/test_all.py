"""Point d'entree pour lancer tous les tests SMTP."""

from __future__ import annotations

import unittest

from tests.smtp_config import (
    test_activate_route,
    test_deactivate_route,
    test_delete_password_route,
    test_get_route,
    test_service,
    test_test_route,
    test_update_route,
    test_validator,
)


TEST_MODULES = (
    test_get_route,
    test_update_route,
    test_activate_route,
    test_deactivate_route,
    test_delete_password_route,
    test_test_route,
    test_service,
    test_validator,
)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement les tests SMTP."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
