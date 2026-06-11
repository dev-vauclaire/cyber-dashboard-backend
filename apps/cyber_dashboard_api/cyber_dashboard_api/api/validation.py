"""Validations legeres partagees par les endpoints."""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_interface


def _contains_control_characters(value: str) -> bool:
    """Retourne True si le texte contient des caracteres de controle."""
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def validate_datetime_range(
    from_at: datetime | None,
    to_at: datetime | None,
) -> None:
    """Verifie qu'une plage de dates est exploitable."""
    if from_at is not None and to_at is not None and from_at > to_at:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_date_range",
            message="Query parameter 'from' must be earlier than or equal to 'to'",
        )


def normalize_optional_filter(
    *,
    name: str,
    value: str | None,
    max_length: int,
) -> str | None:
    """Nettoie un filtre texte optionnel et rejette les valeurs invalides."""
    if value is None:
        return None

    normalized_value = value.strip()
    if not normalized_value:
        return None

    if len(normalized_value) > max_length:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_filter",
            message=f"Query parameter '{name}' exceeds the maximum length of {max_length}",
        )

    if _contains_control_characters(normalized_value):
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_filter",
            message=f"Query parameter '{name}' contains invalid characters",
        )

    return normalized_value


def validate_attacker_ip(attacker_ip: str) -> str:
    """Verifie qu'une IP ou un prefixe CIDR a un format valide."""
    normalized_value = attacker_ip.strip()
    if not normalized_value:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_attacker_ip",
            message="Path parameter 'attacker_ip' must not be blank",
        )

    try:
        ip_interface(normalized_value)
    except ValueError as exc:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_attacker_ip",
            message="Path parameter 'attacker_ip' must be a valid IP address or CIDR",
        ) from exc

    return normalized_value


def validate_source_name(source_name: str) -> str:
    """Nettoie et valide un nom de source simple."""
    normalized_value = source_name.strip()

    if not normalized_value:
        raise ValueError("source_name must not be blank")

    if _contains_control_characters(normalized_value):
        raise ValueError("source_name contains invalid characters")

    return normalized_value


def normalize_optional_text_input(
    *,
    name: str,
    value: str | None,
    max_length: int,
) -> str | None:
    """Nettoie une valeur texte optionnelle de body JSON."""
    if value is None:
        return None

    normalized_value = value.strip()
    if not normalized_value:
        return None

    if len(normalized_value) > max_length:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' exceeds the maximum length of {max_length}",
        )

    if _contains_control_characters(normalized_value):
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' contains invalid characters",
        )

    return normalized_value


def validate_secret_update_input(
    *,
    name: str,
    value: str | None,
    delete_endpoint: str,
    max_length: int = 4096,
) -> str:
    """Valide un secret fourni explicitement dans un payload."""
    if value is None:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' must not be null. Use {delete_endpoint} to remove it",
        )

    normalized_value = value.strip()
    if not normalized_value:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' must not be blank. Use {delete_endpoint} to remove it",
        )

    if len(normalized_value) > max_length:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' exceeds the maximum length of {max_length}",
        )

    if _contains_control_characters(normalized_value):
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' contains invalid characters",
        )

    return normalized_value

def validate_email_input(
    *,
    name: str,
    value: str | None,
    max_length: int = 254,
    delete_endpoint: str | None = None,
) -> str:
    """Valide une adresse email fournie explicitement dans un payload."""
    if value is None:
        from cyber_dashboard_api.api.errors import BadRequestError

        delete_hint = (
            f" Use {delete_endpoint} to remove it"
            if delete_endpoint is not None
            else ""
        )
        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' must not be null.{delete_hint}",
        )

    normalized_value = value.strip()
    if not normalized_value:
        from cyber_dashboard_api.api.errors import BadRequestError

        delete_hint = (
            f" Use {delete_endpoint} to remove it"
            if delete_endpoint is not None
            else ""
        )
        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' must not be blank.{delete_hint}",
        )
    
    if len(normalized_value) > max_length:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' exceeds the maximum length of {max_length}",
        )

    if _contains_control_characters(normalized_value):
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' contains invalid characters",
        )

    # Validation basique du format de l'email
    if "@" not in normalized_value or normalized_value.startswith("@") or normalized_value.endswith("@"):
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' must be a valid email address",
        )

    return normalized_value


def validate_positive_int_field(
    *,
    name: str,
    value: int,
) -> int:
    """Verifie qu'un entier de payload est strictement positif."""
    if value <= 0:
        from cyber_dashboard_api.api.errors import BadRequestError

        raise BadRequestError(
            code="invalid_payload",
            message=f"Field '{name}' must be a strictly positive integer",
        )
    return value
