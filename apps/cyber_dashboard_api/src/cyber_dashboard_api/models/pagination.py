"""Modeles internes de pagination."""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil


@dataclass(frozen=True, slots=True)
class Pagination:
    """Represente les parametres et metadonnees de pagination."""

    page: int
    page_size: int
    total_items: int = 0

    @property
    def offset(self) -> int:
        """Retourne l'offset SQL associe a la page."""
        return (self.page - 1) * self.page_size

    @property
    def total_pages(self) -> int:
        """Retourne le nombre total de pages."""
        if self.total_items == 0:
            return 0
        return ceil(self.total_items / self.page_size)
