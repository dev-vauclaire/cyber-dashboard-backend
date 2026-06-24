from __future__ import annotations

from ipaddress import ip_address, ip_interface


class IpAddress:
    # Responsabilite : representer une adresse IP manipulee par le domaine metier.

    def __init__(self, value: str) -> None:
        # Initialiser l'objet a partir d'une valeur brute.
        self.value = value.strip()
        self._normalized_value: str | None = None

    def normalize(self) -> str:
        # Retourner une representation normalisee de l'adresse IP.
        if self._normalized_value is None:
            self._normalized_value = self._normalize_value(self.value)
        return self._normalized_value

    def is_valid(self) -> bool:
        # Verifier que l'adresse IP respecte un format acceptable.
        try:
            self.normalize()
        except ValueError:
            return False
        return True

    def __str__(self) -> str:
        return self.normalize() if self.is_valid() else self.value

    @staticmethod
    def _normalize_value(raw_value: str) -> str:
        try:
            return ip_address(raw_value).compressed
        except ValueError:
            # PostgreSQL peut renvoyer un INET avec suffixe /32 ou /128.
            # Le correlateur travaille sur l'adresse hote, pas sur le masque.
            return ip_interface(raw_value).ip.compressed
