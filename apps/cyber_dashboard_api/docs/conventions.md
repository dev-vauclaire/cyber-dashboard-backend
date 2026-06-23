# Conventions API

Ce document definit les conventions a suivre pour faire evoluer
`apps/cyber_dashboard_api` dans le monorepo `cyber-dashboard-backend`.

## Positionnement dans le monorepo

L'API est une application du dossier `apps/`.

Structure cible :

```text
cyber-dashboard-backend/
├── alembic/
├── apps/
│   ├── cyber_dashboard_api/
│   ├── scheduler/
│   └── common_ip/
└── packages/
    ├── common/
    └── database/
```

Principe :

- `apps/` contient les executables ;
- `packages/` contient le code partage ;
- `packages/database/models` est la source de verite du schema SQLAlchemy ;
- `packages/database/repositories` contient les repositories reutilisables ;
- `packages/common` contient les helpers transverses comme le chiffrement.

## Structure de l'application API

```text
apps/cyber_dashboard_api/
├── cyber_dashboard_api/
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
│   ├── _runtime.py
│   └── main.py
├── docs/
├── scripts/
├── tests/
├── Dockerfile
├── Dockerfile.dev
└── requirements.txt
```

## Role de chaque dossier

### `cyber_dashboard_api/api`

Couche HTTP FastAPI.

Responsabilites :

- declarer les routes ;
- typer les requetes et reponses ;
- valider les params simples ;
- uniformiser les erreurs ;
- appeler les services et repositories appropries.

Interdit dans cette couche :

- SQL ;
- logique metier longue ;
- appels HTTP externes directs.

### `cyber_dashboard_api/api/routes`

Un fichier par domaine fonctionnel.

Exemples :

- `alerts.py`
- `attacks.py`
- `sources.py`
- `stats.py`
- `cti_config.py`

Convention :

- route courte et lisible ;
- logs de base coherents ;
- pas de logique metier complexe dans les handlers.

### `cyber_dashboard_api/api/schemas`

Schemas Pydantic de contrat public.

Conventions de nommage :

- `...Schema` : objet public simple ;
- `...RequestSchema` : body entrant ;
- `...ResponseSchema` : enveloppe de reponse ;
- `...ItemSchema` : element d'une liste.

### `cyber_dashboard_api/config`

Configuration centralisee.

Regles :

- toute nouvelle variable d'environnement est declaree ici ;
- aucune lecture directe de `os.environ` ailleurs dans l'app.

### `cyber_dashboard_api/db`

Facade locale vers `packages.database.db`.

Raison d'etre :

- garder des imports stables cote API ;
- construire l'acces DB avec les settings de l'application.

### `cyber_dashboard_api/repositories`

Facade locale vers `packages.database.repositories`.

Regle :

- la logique SQL partagee doit vivre dans
`packages/database/repositories` ;
- l'API ne reimplemente pas ses propres
repositories si une version partagee existe deja.

### `cyber_dashboard_api/services`

Orchestration metier.

Responsabilites :

- appliquer les regles metier ;
- orchestrer plusieurs repositories ;
- piloter les integrations externes ;
- gerer les secrets et validations reelles.

### `cyber_dashboard_api/integrations`

Connecteurs externes.

Sous-domaines actuels :

- `cti/`
- `smtp/`
- `attacks_collectors/`

Regles :

- un client externe vit ici ;
- les specificites fournisseur sont encapsulees ici ;
- les services consomment ces clients via des abstractions simples.

### `cyber_dashboard_api/models`

Modeles internes non exposes comme contrat HTTP.

Exemples :

- pagination ;
- filtres.

### `cyber_dashboard_api/utils`

Helpers techniques transverses.

Exemple principal :

- bootstrap de logs.

### `docs`

Documentation locale de l'application.

Fichiers cibles :

- `README.md` : vue d'ensemble et demarrage ;
- `docs/api_doc.md` : catalogue des endpoints ;
- `docs/conventions.md` : conventions de structure ;
- `docs/testing.md` : strategie de tests ;
- `docs/CTI.md` : details d'integration CTI.

### `scripts`

Scripts operatoires non metier.

Usage typique :

- smoke test localhost ;
- controle rapide d'infra locale ;
- utilitaires de validation manuelle.

### `tests`

Tests unitaires et tests de comportement local.

Organisation recommandee :

- un sous-dossier par domaine ;
- `test_all.py` par domaine si plusieurs fichiers ;
- `tests/test_all.py` comme agregateur global.

Priorites de test :

- services ;
- routes ;
- validations ;
- cas d'erreur metier.

## Flux standard d'une requete

Flux cible :

1. la route FastAPI lit la requete ;
2. la route valide les params simples ;
3. la route appelle un service ou un repository ;
4. le service applique la logique metier si necessaire ;
5. le repository partage lit ou ecrit en base ;
6. la route renvoie un schema stable.

## Regles de partage de code

- si une app a besoin d'un repository partage, il doit etre place dans
  `packages/database/repositories` ;
- si une app a besoin d'un helper technique partage, il doit etre place dans
  `packages/common` ;
- le code partage ne doit pas importer `cyber_dashboard_api` ;
- l'app peut exposer une facade locale pour garder ses imports historiques.

## Regles Docker

- les builds de `cyber_dashboard_api` partent de la racine du monorepo ;
- les images doivent copier `apps/cyber_dashboard_api` et `packages/` ;
- les images doivent tourner en utilisateur non-root ;
- le Docker dev doit monter le code applicatif et le code partage.
