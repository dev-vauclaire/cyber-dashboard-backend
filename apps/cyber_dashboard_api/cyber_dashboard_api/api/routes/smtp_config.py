"""Routes REST pour la configuration SMTP."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from cyber_dashboard_api.api.dependencies import (
    get_smtp_config_service,
    get_smtp_email_service,
)
from cyber_dashboard_api.api.schemas import (
    SmtpConfigSchema,
    SmtpConfigUpdateRequestSchema,
    SmtpEmailRequestSchema,
    SmtpEmailResponseSchema,
)
from cyber_dashboard_api.services import SmtpConfigService, SmtpEmailService


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/smtp-config", tags=["smtp-config"])


@router.get("", response_model=SmtpConfigSchema)
def get_smtp_config(
    smtp_config_service: SmtpConfigService = Depends(get_smtp_config_service),
) -> SmtpConfigSchema:
    """Retourne la configuration SMTP publique."""
    logger.info("endpoint=smtp_config_get event=requested")
    return SmtpConfigSchema(**smtp_config_service.get_config())


@router.put("", response_model=SmtpConfigSchema)
@router.patch("", response_model=SmtpConfigSchema)
def update_smtp_config(
    payload: SmtpConfigUpdateRequestSchema,
    smtp_config_service: SmtpConfigService = Depends(get_smtp_config_service),
) -> SmtpConfigSchema:
    """Met a jour partiellement la configuration SMTP."""
    logger.info("endpoint=smtp_config_update event=requested")
    return SmtpConfigSchema(**smtp_config_service.update_config(payload))


@router.post("/activate", response_model=SmtpConfigSchema)
def activate_smtp_config(
    smtp_config_service: SmtpConfigService = Depends(get_smtp_config_service),
) -> SmtpConfigSchema:
    """Active la configuration SMTP."""
    logger.info("endpoint=smtp_config_activate event=requested")
    return SmtpConfigSchema(**smtp_config_service.activate_config())


@router.post("/test", response_model=SmtpConfigSchema)
def test_smtp_config(
    smtp_config_service: SmtpConfigService = Depends(get_smtp_config_service),
) -> SmtpConfigSchema:
    """Teste la configuration SMTP sans changer son activation."""
    logger.info("endpoint=smtp_config_test event=requested")
    return SmtpConfigSchema(**smtp_config_service.test_config())


@router.post("/send-email", response_model=SmtpEmailResponseSchema)
def send_smtp_email(
    payload: SmtpEmailRequestSchema,
    smtp_email_service: SmtpEmailService = Depends(get_smtp_email_service),
) -> SmtpEmailResponseSchema:
    """Envoie un email avec la configuration SMTP active."""
    logger.info("endpoint=smtp_config_send_email event=requested")
    return SmtpEmailResponseSchema(
        **smtp_email_service.send_email(payload=payload)
    )


@router.post("/deactivate", response_model=SmtpConfigSchema)
def deactivate_smtp_config(
    smtp_config_service: SmtpConfigService = Depends(get_smtp_config_service),
) -> SmtpConfigSchema:
    """Desactive la configuration SMTP."""
    logger.info("endpoint=smtp_config_deactivate event=requested")
    return SmtpConfigSchema(**smtp_config_service.deactivate_config())


@router.delete("/password", response_model=SmtpConfigSchema)
def delete_smtp_password(
    smtp_config_service: SmtpConfigService = Depends(get_smtp_config_service),
) -> SmtpConfigSchema:
    """Supprime le mot de passe SMTP."""
    logger.info("endpoint=smtp_config_delete_password event=requested")
    return SmtpConfigSchema(**smtp_config_service.delete_password())
