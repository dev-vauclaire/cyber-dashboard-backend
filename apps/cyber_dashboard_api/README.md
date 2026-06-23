# CYBER DASHBOARD API

API FastAPI du backend Cyber Dashboard.

Cette application expose les endpoints REST utilises par le frontend. Elle
couvre deux besoins :

- consultation des donnees cyber stockees en base PostgreSQL ;
- administration simple des configurations backend necessaires au produit.

Dans le monorepo, `cyber_dashboard_api` reutilise du code partage au lieu de
redefinir sa propre couche SQL :

- `packages/database` : connexion PostgreSQL, modeles SQLAlchemy, repositories
  communs ;
- `packages/common` : services transverses, notamment le chiffrement des secrets.

## Role de l'application

L'API centralise aujourd'hui :

- les endpoints de consultation : dashboard, attaques, alertes, sources,
  statistiques ;
- les endpoints de configuration : CTI, SMTP, collecteurs d'attaques,
  retention ;
- les integrations externes de validation et d'enrichissement appelees a la demande.

Ce n'est donc plus une API strictement read-only : le coeur cyber reste en
lecture, mais la partie configuration ecrit en base.

## Structure utile

```text
apps/cyber_dashboard_api/
├── cyber_dashboard_api/
│   ├── api/                # routes FastAPI, schemas, validation et gestion d'erreurs
│   ├── config/             # lecture des variables d'environnement
│   ├── db/                 # facade locale vers packages.database.db
│   ├── integrations/       # clients/validateurs CTI, SMTP et collecteurs
│   ├── models/             # filtres et objets internes a l'API
│   ├── repositories/       # facade locale vers packages.database.repositories
│   ├── services/           # orchestration metier des routes
│   ├── utils/              # logging et helpers simples
│   ├── _runtime.py         # bootstrap du PYTHONPATH pour retrouver le monorepo
│   └── main.py             # point d'entree FastAPI
├── docs/
│   ├── CTI.md
│   └── conventions.md
├── tests/
├── Dockerfile
├── Dockerfile.dev
└── requirements.txt
```

## Demarrage local

Depuis `apps/cyber_dashboard_api` :

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn cyber_dashboard_api.main:app \
  --host 127.0.0.1 \
  --port 8000 \
  --reload \
  --reload-dir cyber_dashboard_api \
  --reload-dir ../../packages
```

Documentation interactive :

- Swagger UI : `http://127.0.0.1:8000/docs`
- OpenAPI JSON : `http://127.0.0.1:8000/openapi.json`

Le bootstrap `cyber_dashboard_api/_runtime.py` ajoute automatiquement la racine
`cyber-dashboard-backend` au `PYTHONPATH`. Les imports `packages.*` fonctionnent
ainsi meme si l'application est lancee depuis son sous-dossier.

En local, il est recommande de cibler explicitement les dossiers surveilles
avec `--reload-dir`. Sinon, Uvicorn peut tenter de surveiller aussi `.venv/` et
atteindre la limite systeme de file watchers.

## Variables d'environnement

Variables minimales :

- `API_NAME`
- `API_HOST`
- `API_PORT`
- `API_LOG_LEVEL`
- `API_DEV_RESPONSE_DELAY_SECONDS`
- `API_DEV_RESPONSE_DELAY_PATHS`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`

Variables pour secrets et validations externes :

- `CYBER_DASHBOARD_SECRET_KEY_FILE`
- `CYBER_DASHBOARD_SECRET_KEY`
- `CYBER_DASHBOARD_VALIDATION_TIMEOUT_SECONDS`
- `CYBER_DASHBOARD_VALIDATION_TEST_IP`
- `OGO_BASE_URL`
- `SERENICITY_BASE_URL`

Le fichier [.env.example](./.env.example) sert de base.

Simulation simple de reponses lentes en developpement :

- `API_DEV_RESPONSE_DELAY_SECONDS=2.0` applique 2 secondes de delai avant
  reponse
- `API_DEV_RESPONSE_DELAY_PATHS=/api/attacks,/api/stats` limite ce delai a
  certains prefixes de routes
- si `API_DEV_RESPONSE_DELAY_PATHS` est vide, le delai s'applique a toutes les
  routes

Priorite de lecture de la cle maitre :

1. `CYBER_DASHBOARD_SECRET_KEY_FILE`
2. `CYBER_DASHBOARD_SECRET_KEY`

## Commandes utiles

Lancer les tests unitaires :

```bash
cd apps/cyber_dashboard_api
. .venv/bin/activate
python -m unittest tests.test_all
```

Verifier uniquement le bootstrap de l'application :

```bash
cd apps/cyber_dashboard_api
. .venv/bin/activate
python -c "import cyber_dashboard_api.main; print('import-ok')"
```

Lancer un smoke test HTTP sur une API locale deja demarree :

```bash
cd apps/cyber_dashboard_api
. .venv/bin/activate
python scripts/test_localhost_routes.py --report-file reports/api-smoke.json
```

Pour couvrir aussi les routes mutables revertibles :

```bash
python scripts/test_localhost_routes.py \
  --include-mutations \
  --report-file reports/api-smoke.json
```

Pour couvrir les routes qui appellent des services externes :

```bash
python scripts/test_localhost_routes.py \
  --include-mutations \
  --include-external \
  --report-file reports/api-smoke.json
```

## Docker

Les builds Docker doivent partir de la racine du monorepo
`cyber-dashboard-backend`, car l'image API depend aussi de `packages/`.

### Image de production

Build :

```bash
docker build \
  -f apps/cyber_dashboard_api/Dockerfile \
  -t cyber-dashboard-api:prod .
```

Run :

```bash
docker run --rm \
  -p 8000:8000 \
  --env-file apps/cyber_dashboard_api/.env \
  cyber-dashboard-api:prod
```

Caracteristiques :

- image Python slim ;
- execution avec utilisateur non-root ;
- healthcheck HTTP sur `/health` ;
- copie limitee a `apps/cyber_dashboard_api` et `packages`.

### Image de developpement

Build :

```bash
docker build \
  -f apps/cyber_dashboard_api/Dockerfile.dev \
  -t cyber-dashboard-api:dev .
```

Run avec rechargement automatique :

```bash
docker run --rm -it \
  -p 8000:8000 \
  --env-file apps/cyber_dashboard_api/.env \
  -v "$(pwd)/apps/cyber_dashboard_api:/app/apps/cyber_dashboard_api" \
  -v "$(pwd)/packages:/app/packages" \
  cyber-dashboard-api:dev
```

L'image dev surveille a la fois le code de l'application et `packages/`, ce qui
permet de travailler sur les composants partages sans reconstruire l'image a
chaque changement.

## Families d'endpoints

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

## Gestion d'erreur

Les erreurs applicatives et de validation renvoient un format stable :

```json
{
  "error": {
    "code": "invalid_date_range",
    "message": "Query parameter 'from' must be earlier than or equal to 'to'"
  }
}
```

## Documentation complementaire

- [docs/conventions.md](./docs/conventions.md) : conventions de structure et
  d'implementation
- [docs/CTI.md](./docs/CTI.md) : logique d'integration CTI et mapping des fournisseurs
- [docs/api_doc.md](./docs/api_doc.md) : catalogue des endpoints HTTP
- [docs/testing.md](./docs/testing.md) : strategie de tests unitaires et smoke
  tests localhost
