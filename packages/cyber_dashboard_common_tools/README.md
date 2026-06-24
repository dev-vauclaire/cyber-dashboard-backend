# cyber-dashboard-common-tools

Package de services techniques partages par les applications du backend.

- Distribution : `cyber-dashboard-common-tools`
- Module Python : `cyber_dashboard_common_tools`
- Source : `src/cyber_dashboard_common_tools/`

Le package expose actuellement le service de chiffrement et ses erreurs :

```python
from cyber_dashboard_common_tools import SecretService
```

Il est declare comme membre du workspace et s'installe depuis la racine :

```bash
uv sync --all-packages --locked
```

Ce package ne doit pas dependre d'une application concrete.
