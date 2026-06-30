# Conventions API

Conventions pour faire evoluer `apps/cyber_dashboard_api` dans le workspace.

## Positionnement dans le monorepo

```text
cyber-dashboard-backend/
├── alembic/
├── apps/
│   ├── cyber_dashboard_api/
│   ├── cyber_dashboard_common_ip/
│   └── cyber_dashboard_scheduler/
└── packages/
    ├── cyber_dashboard_common_tools/
    └── cyber_dashboard_database/
```

- `apps/` contient les executables et leur logique metier propre ;
- `cyber_dashboard_database.models` est la source de verite SQLAlchemy ;
- `cyber_dashboard_database.repositories` contient les acces reutilisables ;
- `cyber_dashboard_common_tools` contient les services techniques partages.

## Structure de l'API

```text
apps/cyber_dashboard_api/
├── src/cyber_dashboard_api/
│   ├── api/
│   │   ├── routes/
│   │   ├── schemas/
│   │   ├── dependencies.py
│   │   ├── errors.py
│   │   ├── router.py
│   │   └── validation.py
│   ├── config/
│   ├── db/
│   ├── integrations/
│   ├── models/
│   ├── repositories/
│   ├── services/
│   ├── utils/
│   └── main.py
├── docs/
├── scripts/
├── tests/
├── Dockerfile
└── pyproject.toml
```

## Responsabilites

### `api`

La couche FastAPI declare les routes et schemas, valide les parametres, traduit
les erreurs et appelle les services. Elle ne contient ni SQL, ni logique metier
longue, ni appel externe direct.

Un fichier de route correspond a un domaine fonctionnel. Les schemas Pydantic
suivent les suffixes `Schema`, `RequestSchema`, `ResponseSchema` et
`ItemSchema` selon leur role.

### `config`

Toute nouvelle variable d'environnement est centralisee ici. Le reste de
l'application ne lit pas directement `os.environ`.

### `db` et `repositories`

Ces dossiers sont des facades locales vers `cyber_dashboard_database`. Le SQL
partage vit dans le package, pas dans l'application.

### `services`

Les services appliquent les regles metier, orchestrent plusieurs repositories
et pilotent les integrations externes.

### `integrations`

Les clients CTI, SMTP et collecteurs encapsulent les particularites de chaque
fournisseur. Les services les consomment via des interfaces simples.

### `models` et `utils`

`models` contient les objets internes qui ne font pas partie du contrat HTTP.
`utils` contient les helpers techniques locaux, comme la configuration des logs.

### `scripts` et `tests`

`scripts` contient les controles operatoires, notamment le smoke test HTTP.
`tests` couvre en priorite services, routes, validations et erreurs metier.

## Flux d'une requete

1. La route lit et valide la requete.
2. Elle appelle un service ou un repository.
3. Le service applique la logique metier et orchestre ses dependances.
4. Le repository partage lit ou ecrit en base.
5. La route renvoie un schema public stable.

## Partage de code

- un repository reutilise rejoint `cyber_dashboard_database.repositories` ;
- un outil technique reutilise rejoint `cyber_dashboard_common_tools` ;
- un package partage n'importe jamais une application ;
- une application peut garder une facade locale pour stabiliser ses imports.

## Workspace et Docker

- les dependances sont declarees dans `pyproject.toml` et verrouillees dans le
  `uv.lock` racine ;
- le bootstrap local se fait avec `uv sync --all-packages --locked` ;
- les builds Docker partent toujours de la racine du monorepo ;
- le Dockerfile expose les cibles `development` et `production` ;
- le runtime de production utilise `appuser` et ne contient pas `uv` ;
- la cible de developpement monte `apps/cyber_dashboard_api/src` et `packages`.
