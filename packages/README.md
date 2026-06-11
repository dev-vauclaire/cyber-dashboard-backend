# Packages partagés

Le dossier `packages/` contient le code réutilisable par plusieurs applications
du monorepo.

- `database/` : connexion PostgreSQL, modèles SQLAlchemy et repositories communs
- `common/` : services techniques transverses

Règle d'organisation :

- si le code dépend d'un cas d'usage propre à une seule application, il reste
  dans `apps/`
- si le code est stable et réutilisable par plusieurs applications, il va dans
  `packages/`
