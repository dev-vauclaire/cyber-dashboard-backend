"""Bootstrap minimal de logging pour l'API."""

from __future__ import annotations

import logging

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


def configure_logging(log_level: str) -> None:
    """Configure le logger racine une seule fois."""
    root_logger = logging.getLogger()
    normalized_level = getattr(logging, log_level.upper(), logging.INFO)

    if root_logger.handlers:
        root_logger.setLevel(normalized_level)
        return

    logging.basicConfig(level=normalized_level, format=LOG_FORMAT)
