"""Helpers de bootstrap pour l'execution du scheduler dans le monorepo."""

from __future__ import annotations

import sys
from pathlib import Path


def ensure_backend_root_on_path() -> Path:
    """Ajoute la racine backend au PYTHONPATH si necessaire."""
    backend_root = Path(__file__).resolve().parents[2]
    backend_root_str = str(backend_root)
    if backend_root_str not in sys.path:
        sys.path.append(backend_root_str)
    return backend_root
