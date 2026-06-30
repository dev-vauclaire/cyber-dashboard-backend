# cyber-dashboard-database

Source de verite de la base PostgreSQL partagee par les applications.

- Distribution : `cyber-dashboard-database`
- Module Python : `cyber_dashboard_database`
- Source : `src/cyber_dashboard_database/`

Le package contient :

- `models/` : modeles SQLAlchemy et metadata de reference ;
- `db/` : primitives de connexion PostgreSQL et builders partages ;
- `repositories/` : acces aux donnees reutilisables par plusieurs applications.

Ses principales primitives sont exposees depuis le module racine :

```python
from cyber_dashboard_database import Base, PostgresDatabase, metadata
```

Les repositories ne doivent pas dependre d'une application concrete. Toute
evolution de schema est d'abord refletee dans `models/`, puis portee dans une
migration sous `alembic/`.

Installation dans le workspace :

```bash
uv sync --all-packages --locked
```
