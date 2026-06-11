# Applications

Le dossier `apps/` contient les exécutables du backend.

- `cyber_dashboard_api` expose les routes REST et les validations d'entrée.
- `scheduler` collecte les inventaires et les attaques depuis les collecteurs.
- `common_ip` calcule les alertes d'IP communes à partir des attaques stockées.

Chaque application garde :

- son point d'entrée
- sa configuration
- sa logique métier propre
- ses intégrations externes
- ses tests et sa documentation locale

Tout ce qui devient commun à plusieurs applications a vocation à être déplacé
dans `packages/`.
