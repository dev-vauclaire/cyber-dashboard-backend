"""Package principal du correlateur d'IP communes."""

from common_ip_correlator._runtime import ensure_backend_root_on_path
from common_ip_correlator.config import CorrelatorConfig

# Le bootstrap doit etre termine avant le chargement des sous-modules.
ensure_backend_root_on_path()

__all__ = ["CorrelatorConfig"]
