"""Helpers de bootstrap pour l'execution dans le monorepo."""

from __future__ import annotations

import sys
from pathlib import Path


def ensure_backend_root_on_path() -> Path:
    """Ajoute la racine du monorepo backend au PYTHONPATH si necessaire."""
    current_file = Path(__file__).resolve()
    backend_root = next(
        (
            candidate
            for candidate in (current_file.parent, *current_file.parents)
            if (candidate / "packages").is_dir()
        ),
        current_file.parent,
    )
    backend_root_str = str(backend_root)
    if backend_root_str not in sys.path:
        sys.path.append(backend_root_str)
    return backend_root
