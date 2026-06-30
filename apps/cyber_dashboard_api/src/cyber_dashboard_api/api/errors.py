"""Gestion centralisee des erreurs applicatives et HTTP."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from cyber_dashboard_api.api.schemas.errors import (
    ErrorDetailSchema,
    ErrorInfoSchema,
    ErrorResponseSchema,
)

logger = logging.getLogger(__name__)

_EXPECTED_VALUE_MESSAGE_PATTERN = re.compile(r"^Input should be (.+)$")
_MIN_CHARACTERS_MESSAGE_PATTERN = re.compile(
    r"^String should have at least (\d+) character(?:s)?$"
)
_MAX_CHARACTERS_MESSAGE_PATTERN = re.compile(
    r"^String should have at most (\d+) character(?:s)?$"
)

_VALIDATION_MESSAGE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^Field required$"), "Champ requis"),
    (
        re.compile(r"^Extra inputs are not permitted$"),
        "Des champs supplémentaires ne sont pas autorisés",
    ),
    (
        re.compile(r"^Input should be a valid integer(?:, .+)?$"),
        "La valeur doit être un entier valide",
    ),
    (
        re.compile(r"^Input should be a valid number(?:, .+)?$"),
        "La valeur doit être un nombre valide",
    ),
    (
        re.compile(r"^Input should be a valid boolean(?:, .+)?$"),
        "La valeur doit être un booléen valide",
    ),
    (
        re.compile(r"^Input should be a valid string(?:, .+)?$"),
        "La valeur doit être une chaîne de caractères valide",
    ),
    (
        re.compile(r"^Input should be a valid URL(?:, .+)?$"),
        "La valeur doit être une URL valide",
    ),
    (
        re.compile(r"^Input should be a valid email address(?:, .+)?$"),
        "La valeur doit être une adresse e-mail valide",
    ),
    (
        re.compile(r"^Input is not a valid email address(?:, .+)?$"),
        "La valeur doit être une adresse e-mail valide",
    ),
    (
        re.compile(r"^Input should be a valid dictionary(?:, .+)?$"),
        "La valeur doit être un objet valide",
    ),
    (
        re.compile(r"^Input should be a valid list(?:, .+)?$"),
        "La valeur doit être une liste valide",
    ),
    (
        re.compile(r"^Input should be a valid datetime(?:, .+)?$"),
        "La valeur doit être une date et heure valides",
    ),
    (
        re.compile(r"^Input should be a valid date(?:, .+)?$"),
        "La valeur doit être une date valide",
    ),
    (
        re.compile(r"^Input should be a valid IPv4 or IPv6 address(?:, .+)?$"),
        "La valeur doit être une adresse IPv4 ou IPv6 valide",
    ),
    (
        re.compile(r"^Input should be greater than or equal to (.+)$"),
        r"La valeur doit être supérieure ou égale à \1",
    ),
    (
        re.compile(r"^Input should be greater than (.+)$"),
        r"La valeur doit être strictement supérieure à \1",
    ),
    (
        re.compile(r"^Input should be less than or equal to (.+)$"),
        r"La valeur doit être inférieure ou égale à \1",
    ),
    (
        re.compile(r"^Input should be less than (.+)$"),
        r"La valeur doit être strictement inférieure à \1",
    ),
    (
        re.compile(r"^String should match pattern '(.+)'$"),
        r"Le texte ne respecte pas le format attendu : \1",
    ),
)

_HTTP_EXCEPTION_MESSAGE_TRANSLATIONS = {
    "Bad Request": "Requête invalide",
    "Unauthorized": "Non authentifié",
    "Forbidden": "Accès interdit",
    "Not Found": "Ressource introuvable",
    "Method Not Allowed": "Méthode HTTP non autorisée",
    "Unprocessable Entity": "Entité non traitable",
    "Internal Server Error": "Erreur interne du serveur",
}


@dataclass(slots=True)
class ApiError(Exception):
    """Erreur applicative simple exposee proprement au client."""

    status_code: int
    code: str
    message: str
    details: list[ErrorDetailSchema] | None = None


class BadRequestError(ApiError):
    """Erreur 400 applicative."""

    def __init__(
        self,
        *,
        code: str = "bad_request",
        message: str,
        details: list[ErrorDetailSchema] | None = None,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            code=code,
            message=message,
            details=details,
        )


class NotFoundError(ApiError):
    """Erreur 404 applicative."""

    def __init__(
        self,
        *,
        code: str = "not_found",
        message: str,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            code=code,
            message=message,
        )


class ConflictError(ApiError):
    """Erreur 409 applicative."""

    def __init__(
        self,
        *,
        code: str = "conflict",
        message: str,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            code=code,
            message=message,
        )


class ServiceUnavailableError(ApiError):
    """Erreur 503 applicative."""

    def __init__(
        self,
        *,
        code: str = "service_unavailable",
        message: str,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code=code,
            message=message,
        )


def _build_error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetailSchema] | None = None,
) -> JSONResponse:
    """Construit une reponse JSON d'erreur homogene."""
    payload = ErrorResponseSchema(
        error=ErrorInfoSchema(
            code=code,
            message=message,
            details=details,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=payload.model_dump(mode="json", exclude_none=True),
    )


def _normalize_validation_errors(
    errors: list[dict[str, Any]],
) -> list[ErrorDetailSchema]:
    """Transforme les erreurs FastAPI/Pydantic en details simples."""
    normalized_errors: list[ErrorDetailSchema] = []
    for error in errors:
        location = ".".join(str(part) for part in error.get("loc", ()))
        normalized_errors.append(
            ErrorDetailSchema(
                location=location,
                message=_translate_validation_message(
                    str(error.get("msg", "Valeur invalide"))
                ),
                type=error.get("type", "validation_error"),
                input=error.get("input"),
            )
        )
    return normalized_errors


def _translate_validation_message(message: str) -> str:
    """Traduit les messages Pydantic/FastAPI les plus fréquents."""
    normalized_message = message.strip()
    if not normalized_message:
        return "Valeur invalide"

    value_error_prefix = "Value error, "
    if normalized_message.startswith(value_error_prefix):
        return normalized_message[len(value_error_prefix) :]

    assertion_prefix = "Assertion failed, "
    if normalized_message.startswith(assertion_prefix):
        return normalized_message[len(assertion_prefix) :]

    min_characters_match = _MIN_CHARACTERS_MESSAGE_PATTERN.match(normalized_message)
    if min_characters_match:
        character_count = _format_character_count(min_characters_match.group(1))
        return f"Le texte doit contenir au minimum {character_count}"

    max_characters_match = _MAX_CHARACTERS_MESSAGE_PATTERN.match(normalized_message)
    if max_characters_match:
        character_count = _format_character_count(max_characters_match.group(1))
        return f"Le texte doit contenir au maximum {character_count}"

    for pattern, replacement in _VALIDATION_MESSAGE_PATTERNS:
        if pattern.match(normalized_message):
            return pattern.sub(replacement, normalized_message)

    expected_value_match = _EXPECTED_VALUE_MESSAGE_PATTERN.match(normalized_message)
    if expected_value_match:
        expected_value = _translate_expected_value(expected_value_match.group(1))
        return f"La valeur doit être {expected_value}"

    return normalized_message


def _format_character_count(raw_count: str) -> str:
    """Formate un nombre de caracteres avec le bon accord."""
    count = int(raw_count)
    label = "caractère" if count == 1 else "caractères"
    return f"{count} {label}"


def _translate_expected_value(expected_value: str) -> str:
    """Traduit les listes de valeurs attendues produites par Pydantic."""
    translated_value = re.sub(r"\bor\b", "ou", expected_value)
    return (
        translated_value.replace("True", "true")
        .replace("False", "false")
        .replace("None", "null")
    )


def _translate_http_exception_message(message: str) -> str:
    """Traduit les messages HTTP par défaut de Starlette/FastAPI."""
    normalized_message = message.strip()
    if not normalized_message:
        return "Erreur HTTP"
    return _HTTP_EXCEPTION_MESSAGE_TRANSLATIONS.get(
        normalized_message,
        normalized_message,
    )


def register_exception_handlers(application: FastAPI) -> None:
    """Enregistre les handlers d'erreur communs de l'API."""

    @application.exception_handler(ApiError)
    async def handle_api_error(
        request: Request,
        exc: ApiError,
    ) -> JSONResponse:
        logger.warning(
            "path=%s method=%s status=%s code=%s message=%s",
            request.url.path,
            request.method,
            exc.status_code,
            exc.code,
            exc.message,
        )
        return _build_error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            details=exc.details,
        )

    @application.exception_handler(RequestValidationError)
    async def handle_request_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        details = _normalize_validation_errors(exc.errors())
        logger.warning(
            "path=%s method=%s status=%s code=validation_error details=%s",
            request.url.path,
            request.method,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            len(details),
        )
        return _build_error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code="validation_error",
            message="Requête invalide",
            details=details,
        )

    @application.exception_handler(HTTPException)
    async def handle_http_exception(
        request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        details: list[ErrorDetailSchema] | None = None
        message = "Erreur HTTP"

        if isinstance(exc.detail, str):
            message = _translate_http_exception_message(exc.detail)
        elif exc.detail is not None:
            details = [
                ErrorDetailSchema(
                    location="request",
                    message="Détail de l'erreur HTTP",
                    type="http_error",
                    input=exc.detail,
                )
            ]

        logger.warning(
            "path=%s method=%s status=%s code=http_error message=%s",
            request.url.path,
            request.method,
            exc.status_code,
            message,
        )
        return _build_error_response(
            status_code=exc.status_code,
            code="http_error",
            message=message,
            details=details,
        )

    @application.exception_handler(Exception)
    async def handle_unexpected_exception(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        logger.exception(
            "path=%s method=%s status=%s code=internal_server_error",
            request.url.path,
            request.method,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        return _build_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="internal_server_error",
            message="Erreur interne du serveur",
        )
