# Copyright (c) 2026 Vauclaire
#
# Licensed under the EUPL, Version 1.2
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
#
# https://eupl.eu/

"""Point d'entree FastAPI de l'application."""

from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI

from cyber_dashboard_api.api.errors import register_exception_handlers
from cyber_dashboard_api.api.router import api_router
from cyber_dashboard_api.config.settings import get_settings
from cyber_dashboard_api.utils.logging import configure_logging


def _matches_dev_delay_path(
    request_path: str,
    configured_paths: tuple[str, ...],
) -> bool:
    """Retourne vrai si le delai doit s'appliquer a ce chemin."""
    if not configured_paths:
        return True

    return any(request_path.startswith(path_prefix) for path_prefix in configured_paths)


def _build_dev_response_delay_middleware(settings):
    """Construit le middleware de delai HTTP a partir des settings."""

    async def dev_response_delay_middleware(request, call_next):
        if _matches_dev_delay_path(
            request.url.path,
            settings.api_dev_response_delay_paths,
        ):
            await asyncio.sleep(settings.api_dev_response_delay_seconds)
        return await call_next(request)

    return dev_response_delay_middleware


def create_app() -> FastAPI:
    """Construit et configure l'application FastAPI."""
    settings = get_settings()
    configure_logging(settings.api_log_level)
    logger = logging.getLogger(__name__)

    application = FastAPI(
        title=settings.api_name,
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    if settings.api_dev_response_delay_seconds > 0:
        logger.info(
            "Delai de reponse developpement active: %.3fs sur %s",
            settings.api_dev_response_delay_seconds,
            (
                ", ".join(settings.api_dev_response_delay_paths)
                if settings.api_dev_response_delay_paths
                else "toutes les routes"
            ),
        )
        application.middleware("http")(_build_dev_response_delay_middleware(settings))

    register_exception_handlers(application)
    application.include_router(api_router)

    logger.info(
        "Application FastAPI initialisee sur %s:%s",
        settings.api_host,
        settings.api_port,
    )

    return application


app = create_app()
