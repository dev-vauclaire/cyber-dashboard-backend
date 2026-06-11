"""Gestion centralisee des erreurs applicatives et HTTP."""

from __future__ import annotations

import logging
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
                message=error.get("msg", "Invalid value"),
                type=error.get("type", "validation_error"),
                input=error.get("input"),
            )
        )
    return normalized_errors


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
            message="Invalid request parameters",
            details=details,
        )

    @application.exception_handler(HTTPException)
    async def handle_http_exception(
        request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        details: list[ErrorDetailSchema] | None = None
        message = "HTTP error"

        if isinstance(exc.detail, str):
            message = exc.detail
        elif exc.detail is not None:
            details = [
                ErrorDetailSchema(
                    location="request",
                    message="HTTP error detail",
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
            message="Internal server error",
        )
