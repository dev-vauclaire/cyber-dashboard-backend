# Cyber Dashboard API

API FastAPI du backend Cyber Dashboard.
Elle communique avec une base de donnée en lecture écriture.

## Structure

```text
apps/cyber_dashboard_api/
├── src/cyber_dashboard_api/
│   ├── api/                # Routes, Schemas d'entree et de sortie des endpoints
│   ├── config/             # Variables d'environnement
│   ├── db/                 # Connexion, modèles
│   ├── integrations/       # CTI, SMTP et collecteurs
│   ├── models/             # Objets internes
│   ├── repositories/       # Facade vers les repositories partages
│   ├── services/           # Orchestration metier
│   ├── utils/
│   └── main.py             # Entrypoint de l'application
├── docs/
├── scripts/
├── tests/
├── Dockerfile
└── pyproject.toml
```

## Demarrage local

Depuis la racine du monorepo :

```bash
uv sync --all-packages --locked
cp apps/cyber_dashboard_api/.env.example apps/cyber_dashboard_api/.env
make api
```

- Swagger UI : `http://127.0.0.1:8000/docs`
- OpenAPI : `http://127.0.0.1:8000/openapi.json`
- Sante : `http://127.0.0.1:8000/health`

## Variables d'environnement

Variables principales :

- `API_NAME`, `API_HOST`, `API_PORT`, `API_LOG_LEVEL` ;
- `API_DEV_RESPONSE_DELAY_SECONDS`, `API_DEV_RESPONSE_DELAY_PATHS` ;
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` ;
- `CYBER_DASHBOARD_SECRET_KEY_FILE`, `CYBER_DASHBOARD_SECRET_KEY` ;
- `CYBER_DASHBOARD_VALIDATION_TIMEOUT_SECONDS` ;
- `CYBER_DASHBOARD_VALIDATION_TEST_IP` ;
- `OGO_BASE_URL`, `SERENICITY_BASE_URL`.

Le fichier [.env.example](./.env.example) contient les valeurs de depart. La
cle maitre est lue en priorite depuis `CYBER_DASHBOARD_SECRET_KEY_FILE`, puis
depuis `CYBER_DASHBOARD_SECRET_KEY`.

## Tests

Depuis la racine :

```bash
uv run --directory apps/cyber_dashboard_api python -m unittest tests.test_all
```

Verifier uniquement l'import de l'application :

```bash
uv run --package cyber-dashboard-api \
  python -c "import cyber_dashboard_api.main; print('import-ok')"
```

Pour une API locale deja demarree :

```bash
uv run --package cyber-dashboard-api \
  python apps/cyber_dashboard_api/scripts/test_localhost_routes.py \
  --report-file apps/cyber_dashboard_api/reports/api-smoke.json
```

Les options `--include-mutations`, `--include-external` et
`--include-destructive` et leurs precautions sont detaillees dans
[docs/testing.md](./docs/testing.md).

## Docker

Les deux cibles utilisent le meme Dockerfile et doivent etre construites depuis
la racine du monorepo.

### Production

```bash
docker build \
  --target production \
  -f apps/cyber_dashboard_api/Dockerfile \
  -t cyber-dashboard-api:prod .

docker run --rm \
  -p 8000:8000 \
  --env-file apps/cyber_dashboard_api/.env \
  cyber-dashboard-api:prod
```

L'image execute Uvicorn avec `appuser` et declare un healthcheck sur `/health`.

### Developpement

```bash
docker build \
  --target development \
  -f apps/cyber_dashboard_api/Dockerfile \
  -t cyber-dashboard-api:dev .

docker run --rm -it \
  -p 8000:8000 \
  --env-file apps/cyber_dashboard_api/.env \
  -v "$(pwd)/apps/cyber_dashboard_api/src:/app/apps/cyber_dashboard_api/src" \
  -v "$(pwd)/packages:/app/packages" \
  cyber-dashboard-api:dev
```

Cette cible installe les membres du workspace en editable et surveille
`apps/cyber_dashboard_api/src` ainsi que `packages`.

## Principales familles d'endpoints

- `GET /health`
- `GET /api/dashboard/overview`
- `GET /api/sources/*`
- `GET /api/alerts/*`
- `GET /api/stats/*`
- `GET /api/attacks`
- `GET|PATCH|POST|DELETE /api/cti-config/*`
- `GET /api/cti/*`
- `GET|PUT|POST|DELETE /api/smtp-config/*`
- `GET|POST|PATCH|DELETE /api/attacks-collector-config/*`
- `GET|PATCH /api/retention-policies/*`

Les erreurs applicatives utilisent une enveloppe stable :

```json
{
  "error": {
    "code": "invalid_date_range",
    "message": "Le paramètre de requête 'from' doit être antérieur ou égal à 'to'"
  }
}
```

## Documentation complementaire

- [Conventions](./docs/conventions.md)
- [Strategie de tests](./docs/testing.md)
- [Integration CTI](./docs/CTI.md)
- [Catalogue des endpoints](./docs/api_doc.md)
