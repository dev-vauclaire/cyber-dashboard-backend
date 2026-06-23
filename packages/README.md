# Packages partagés

Le dossier `packages/` contient les libraries réutilisable par plusieurs applications
du monorepo.

- `cyber-dashboard-database/` : connexion PostgreSQL, modèles
SQLAlchemy et repositories communs
- `cyber-dashboard-common-tools/` : services techniques transverses comme le chiffrement

Règle d'organisation :

- si le code dépend d'un cas d'usage propre à une seule application, il reste
  dans `apps/`
- si le code est stable et réutilisable par plusieurs applications, il va dans
  `packages/`
