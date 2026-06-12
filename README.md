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

## Prochaine étape de mutualisation

- finaliser la bascule de `scheduler` vers `packages/database`
- extraire les composants purement communs hors des applications
- garder un seul contrat de base de données pour les trois apps
