# cyber-dashboard-backend

Monorepo backend de Cyber Dashboard.

Il regroupe trois applications Python et les briques partagées dont elles ont
besoin :

- `apps/cyber_dashboard_api` : API REST FastAPI
- `apps/scheduler` : collecteur et scheduler des attaques
- `apps/common_ip` : corrélateur d'IP communes
- `packages/database` : source de vérité BDD, connexion PostgreSQL et
  repositories communs
- `packages/common` : services transverses partagés, comme le chiffrement
- `alembic` : historique des migrations de schéma

## Structure

```text
cyber-dashboard-backend/
├── alembic/
├── apps/
│   ├── cyber_dashboard_api/
│   ├── scheduler/
│   └── common_ip/
├── packages/
│   ├── common/
│   └── database/
└── README.md
```

## Principes d'organisation

- Les applications vivent dans `apps/` et gardent leur logique métier propre.
- Le schéma SQLAlchemy de référence vit dans `packages/database/models`.
- Les repositories réutilisables entre apps vivent dans
  `packages/database/repositories`.
- Les services techniques partagés vivent dans `packages/common`.
- Les migrations Alembic décrivent l'évolution du schéma commun du backend.

## Bootstrap de migration Alembic

Le script [`scripts/migrate.py`](./scripts/migrate.py) sert de point d'entrée
robuste pour migrer une base selon son état réel.

Cas gérés :

1. Base vide :
   `python scripts/migrate.py` détecte l'absence de tables métier et lance
   `alembic upgrade head`.
2. Base V1 legacy non stampée :
   le script détecte le schéma V1 historique, exécute
   `alembic stamp 6d98af97a0e5`, puis `alembic upgrade head`.
3. Base déjà versionnée Alembic :
   le script lit `alembic_version`, affiche la révision courante et lance
   `alembic upgrade head`.

Variables attendues :

- `DATABASE_URL` : URL SQLAlchemy complète de la base PostgreSQL cible ;
- `V1_BASELINE_REVISION` : optionnelle, surcharge la baseline V1 par défaut
  `6d98af97a0e5`.

Commandes :

```bash
python scripts/migrate.py
```

Exemple Docker one-shot futur :

```bash
docker compose run --rm migrate
```

## Prochaine étape de mutualisation

- finaliser la bascule de `scheduler` vers `packages/database`
- extraire les composants purement communs hors des applications
- garder un seul contrat de base de données pour les trois apps
