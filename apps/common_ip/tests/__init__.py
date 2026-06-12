"""Suite de tests du correlateur common_ip."""

from __future__ import annotations

import sys
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT_STR = str(APP_ROOT)

if APP_ROOT_STR not in sys.path:
    sys.path.append(APP_ROOT_STR)
