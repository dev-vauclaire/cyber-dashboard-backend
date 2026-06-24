# Cyber Dashboard Scheduler

Worker d'inventaire, de collecte des attaques et de retention. La distribution
`cyber-dashboard-scheduler` fournit le module `cyber_dashboard_scheduler` et la
commande `cyber-scheduler`.

## Fonctionnement

A chaque cycle, le scheduler :

1. lit les configurations de collecteurs actives ;
2. dechiffre leurs secrets avec `cyber_dashboard_common_tools` ;
3. inventorie les sources OGO et Serenicity ;
4. collecte et normalise les attaques ;
5. insere les nouvelles attaques avec un identifiant de deduplication stable ;
6. met a jour `scheduler_state.last_poll_at` ;
7. applique les politiques de retention actives.

## Structure

```text
apps/cyber_dashboard_scheduler/
├── src/cyber_dashboard_scheduler/
│   ├── clients/
│   ├── config/
│   ├── db/
│   ├── models/
│   ├── services/
│   ├── utils/
│   └── main.py
├── tests/
├── Dockerfile
└── pyproject.toml
```

## Demarrage local

Depuis la racine :

```bash
uv sync --all-packages --locked
cp apps/cyber_dashboard_scheduler/.env.example \
  apps/cyber_dashboard_scheduler/.env
make scheduler
```

Commande equivalente :

```bash
uv run --package cyber-dashboard-scheduler cyber-scheduler
```

L'application charge automatiquement
`apps/cyber_dashboard_scheduler/.env`. Elle doit utiliser la meme cle maitre
que l'API.

## Variables d'environnement

Variables obligatoires :

- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` ;
- `LIMIT_REQUEST_PER_DAY`, `LOG_LEVEL` ;
- `OGO_BASE_URL`, `SERENICITY_BASE_URL`.

Variables optionnelles :

- `HTTP_TIMEOUT_SECONDS`, valeur par defaut `10` ;
- `POLL_SAFETY_WINDOW_SECONDS`, valeur par defaut `300` ;
- `CYBER_DASHBOARD_SECRET_KEY_FILE` ;
- `CYBER_DASHBOARD_SECRET_KEY`.

Le fichier [.env.example](./.env.example) contient un exemple complet.

## Tests

Le smoke test verifie le point d'entree sans demarrer la boucle ni contacter
PostgreSQL :

```bash
uv run --directory apps/cyber_dashboard_scheduler \
  python -m unittest discover -s tests -t .
```

## Docker

Depuis la racine :

```bash
docker build \
  -f apps/cyber_dashboard_scheduler/Dockerfile \
  -t cyber-dashboard-scheduler:prod .

docker run --rm \
  --env-file apps/cyber_dashboard_scheduler/.env \
  cyber-dashboard-scheduler:prod
```
