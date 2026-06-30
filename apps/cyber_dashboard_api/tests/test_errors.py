"""Tests du format et des messages d'erreur API."""

from __future__ import annotations

import json
import unittest

from cyber_dashboard_api.api.errors import (
    _build_error_response,
    _normalize_validation_errors,
)


class ErrorHandlerTestCase(unittest.TestCase):
    """Couvre les messages d'erreur HTTP exposes au client."""

    def test_validation_error_response_message_is_french(self) -> None:
        details = _normalize_validation_errors(
            [
                {
                    "loc": ("body", "name"),
                    "msg": "String should have at least 1 character",
                    "type": "string_too_short",
                    "input": "",
                }
            ]
        )

        response = _build_error_response(
            status_code=422,
            code="validation_error",
            message="Requête invalide",
            details=details,
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            json.loads(response.body),
            {
                "error": {
                    "code": "validation_error",
                    "message": "Requête invalide",
                    "details": [
                        {
                            "location": "body.name",
                            "message": (
                                "Le texte doit contenir au minimum 1 caractère"
                            ),
                            "type": "string_too_short",
                            "input": "",
                        }
                    ],
                }
            },
        )

    def test_literal_validation_translates_expected_values(self) -> None:
        details = _normalize_validation_errors(
            [
                {
                    "loc": ("query", "kind"),
                    "msg": "Input should be 'ogo' or 'serenicity'",
                    "type": "literal_error",
                    "input": "other",
                }
            ]
        )

        self.assertEqual(
            details[0].message,
            "La valeur doit être 'ogo' ou 'serenicity'",
        )


if __name__ == "__main__":
    unittest.main()
