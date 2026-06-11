# Applications

Le dossier `apps/` contient les executables du monorepo backend.

Applications actuelles :

- `cyber_dashboard_api` : expose l'API REST FastAPI, les validations HTTP et les routes de configuration.
- `scheduler` : collecte les inventaires et les attaques depuis les collecteurs actifs.
- `common_ip` : calcule les alertes d'IP communes a partir des attaques stockees.

Chaque application garde localement :

- son point d'entree ;
- ses Dockerfiles ;
- sa configuration ;
- sa logique metier propre ;
- ses integrations externes ;
- ses tests ;
- sa documentation locale.

Tout ce qui doit etre partage entre plusieurs applications a vocation a vivre dans `packages/`.

Regle pratique :

- si un modele SQLAlchemy ou un repository est utilise par plusieurs apps, il doit etre defini dans `packages/database` ;
- si un helper technique transverse est reutilisable, il doit etre defini dans `packages/common`.
