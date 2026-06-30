"""Sous-package des services de collecte d'attaques du scheduler."""

from .collection_common import (
    CollectionWindow,
    build_collection_window,
    persist_collection_error,
    persist_collection_success,
)
from .lurio_collection import LurioAttackCollectionResult, LurioAttackCollectionService
from .ogo_collection import OgoAttackCollectionResult, OgoAttackCollectionService
from .serenicity_sensor_collection import (
    SerenicitySensorAttackCollectionResult,
    SerenicitySensorAttackCollectionService,
)

__all__ = [
    "CollectionWindow",
    "LurioAttackCollectionResult",
    "LurioAttackCollectionService",
    "OgoAttackCollectionResult",
    "OgoAttackCollectionService",
    "SerenicitySensorAttackCollectionResult",
    "SerenicitySensorAttackCollectionService",
    "build_collection_window",
    "persist_collection_error",
    "persist_collection_success",
]
