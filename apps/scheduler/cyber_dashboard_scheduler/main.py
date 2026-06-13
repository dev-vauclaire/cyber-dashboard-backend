"""Point d'entrée exécutable pour l'application scheduler."""

from __future__ import annotations

import logging

from packages.common.secret_service import SecretService
from packages.database.db import PostgresDatabase

from cyber_dashboard_scheduler.clients import OgoApiClient
from cyber_dashboard_scheduler.config import ConfigurationError, Settings
from cyber_dashboard_scheduler.services import (
    SchedulerRuntimeService,
    SourceInventoryService,
)
from cyber_dashboard_scheduler.utils.logging import configure_logging


LOGGER = logging.getLogger(__name__)


def main() -> int:
    """Charge la configuration et démarre le bootstrap du scheduler."""
    try:
        settings = Settings.from_env()
    except ConfigurationError as exc:
        configure_logging("ERROR")
        LOGGER.error("Échec du démarrage du scheduler : %s", exc)
        return 1

    configure_logging(settings.log_level)
    LOGGER.info(
        "Configuration du scheduler chargée pour la base %s:%s/%s",
        settings.database.host,
        settings.database.port,
        settings.database.name,
    )
    LOGGER.info(
        "Scheduler démarré avec succès avec une limite de %s requêtes/jour",
        settings.limit_request_per_day,
    )
    LOGGER.info(
        "Timeout HTTP configuré à %.1f secondes",
        settings.http_timeout_seconds,
    )

    database = PostgresDatabase(settings.database)
    secret_service = SecretService(settings)

    inventory_ogo_client = OgoApiClient(
        base_url=settings.ogo.base_url,
        timeout_seconds=settings.http_timeout_seconds,
    )

    LOGGER.info(
        "Seul le module d'inventaire est activé à cette étape. "
        "Les collecteurs d'attaques seront rebranchés après leur migration dédiée."
    )

    runtime_service = SchedulerRuntimeService(
        settings=settings,
        database=database,
        inventory_service=SourceInventoryService(
            settings=settings,
            database=database,
            secret_service=secret_service,
            ogo_client=inventory_ogo_client,
        ),
        ogo_collection_runner=None,
        sensor_collection_runner=None,
        lurio_collection_runner=None,
    )

    try:
        runtime_service.run_forever()
    except KeyboardInterrupt:
        LOGGER.info("Arrêt du scheduler demandé par l'utilisateur")
        return 0
    except Exception as exc:
        LOGGER.error("Échec du scheduler : %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
