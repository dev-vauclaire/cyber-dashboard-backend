"""Exports paresseux des modeles SQLAlchemy du schema partage."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__all__ = [
    "Attack",
    "AttacksCollectorConfig",
    "AttacksCollectorType",
    "Base",
    "CommonIpAlert",
    "CommonIpAlertSource",
    "CorrelationStatus",
    "CtiConfig",
    "OgoSource",
    "RetentionPolicy",
    "SchedulerState",
    "SerenicitySource",
    "SensorType",
    "SmtpConfig",
    "Source",
    "attacks_collector_type_enum",
    "load_all_models",
    "metadata",
    "status_correlation_enum",
]

_MODEL_MODULES = (
    ".attack",
    ".attacks_collector_config",
    ".common_ip_alert",
    ".common_ip_alert_source",
    ".cti_config",
    ".ogo_source",
    ".retention_policies",
    ".scheduler_state",
    ".sensor_type",
    ".serenicity_source",
    ".smtp_config",
    ".source",
)

_EXPORTS: dict[str, tuple[str, str]] = {
    "Attack": (".attack", "Attack"),
    "AttacksCollectorConfig": (".attacks_collector_config", "AttacksCollectorConfig"),
    "AttacksCollectorType": (".enums", "AttacksCollectorType"),
    "Base": (".base", "Base"),
    "CommonIpAlert": (".common_ip_alert", "CommonIpAlert"),
    "CommonIpAlertSource": (".common_ip_alert_source", "CommonIpAlertSource"),
    "CorrelationStatus": (".enums", "CorrelationStatus"),
    "CtiConfig": (".cti_config", "CtiConfig"),
    "OgoSource": (".ogo_source", "OgoSource"),
    "RetentionPolicy": (".retention_policies", "RetentionPolicy"),
    "SchedulerState": (".scheduler_state", "SchedulerState"),
    "SerenicitySource": (".serenicity_source", "SerenicitySource"),
    "SensorType": (".sensor_type", "SensorType"),
    "SmtpConfig": (".smtp_config", "SmtpConfig"),
    "Source": (".source", "Source"),
    "attacks_collector_type_enum": (".sqlalchemy_enums", "attacks_collector_type_enum"),
    "status_correlation_enum": (".sqlalchemy_enums", "status_correlation_enum"),
}


def load_all_models() -> None:
    """Load every mapped model so Base.metadata contains the full schema."""
    for module_name in _MODEL_MODULES:
        import_module(module_name, __name__)


def __getattr__(name: str) -> Any:
    """Charge uniquement l'export demandé."""
    if name == "metadata":
        load_all_models()
        base_module = import_module(".base", __name__)
        return base_module.Base.metadata

    export_target = _EXPORTS.get(name)
    if export_target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attribute_name = export_target
    module = import_module(module_name, __name__)
    return getattr(module, attribute_name)


if TYPE_CHECKING:
    from .attack import Attack
    from .attacks_collector_config import AttacksCollectorConfig
    from .base import Base
    from .common_ip_alert import CommonIpAlert
    from .common_ip_alert_source import CommonIpAlertSource
    from .cti_config import CtiConfig
    from .enums import (
        AttacksCollectorType,
        CorrelationStatus,
    )
    from .sqlalchemy_enums import attacks_collector_type_enum, status_correlation_enum
    from .ogo_source import OgoSource
    from .retention_policies import RetentionPolicy
    from .scheduler_state import SchedulerState
    from .sensor_type import SensorType
    from .serenicity_source import SerenicitySource
    from .smtp_config import SmtpConfig
    from .source import Source
