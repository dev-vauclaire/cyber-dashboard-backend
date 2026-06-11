# Package database

`packages/database` centralise l'accès au schéma et aux données partagées du
backend.

Sous-dossiers :

- `models/` : source de vérité SQLAlchemy de la base de données
- `db/` : primitives de connexion PostgreSQL
- `repositories/` : accès aux données réutilisables par plusieurs apps

Règle importante :

- toute évolution de schéma doit d'abord être reflétée dans `models/`, puis
  portée dans `alembic/`
