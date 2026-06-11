# Copyright (c) 2026 Vauclaire
#
# Licensed under the EUPL, Version 1.2
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
#
# https://eupl.eu/

"""Point d'entree FastAPI de l'application."""

from __future__ import annotations

import logging

from fastapi import FastAPI

from cyber_dashboard_api.api.errors import register_exception_handlers
from cyber_dashboard_api.api.router import api_router
from cyber_dashboard_api.config.settings import get_settings
from cyber_dashboard_api.utils.logging import configure_logging


def create_app() -> FastAPI:
    """Construit et configure l'application FastAPI."""
    settings = get_settings()
    configure_logging(settings.api_log_level)

    application = FastAPI(
        title=settings.api_name,
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    register_exception_handlers(application)
    application.include_router(api_router)

    logger = logging.getLogger(__name__)
    logger.info(
        "Application FastAPI initialisee sur %s:%s",
        settings.api_host,
        settings.api_port,
    )

    return application


app = create_app()
