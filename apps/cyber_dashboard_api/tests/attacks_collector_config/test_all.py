"""Point d'entree pour lancer tous les tests attacks_collector_config."""

from __future__ import annotations

import unittest

from tests.attacks_collector_config import (
    test_activate_route,
    test_create_route,
    test_deactivate_route,
    test_delete_api_key_route,
    test_delete_email_route,
    test_delete_route,
    test_get_route,
    test_list_route,
    test_request_inventory_route,
    test_update_route,
)


ROUTE_TEST_MODULES = (
    test_activate_route,
    test_create_route,
    test_deactivate_route,
    test_delete_api_key_route,
    test_delete_email_route,
    test_delete_route,
    test_get_route,
    test_list_route,
    test_request_inventory_route,
    test_update_route,
)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Assemble explicitement tous les tests unitaires du dossier."""
    del tests, pattern

    suite = unittest.TestSuite()
    for module in ROUTE_TEST_MODULES:
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
