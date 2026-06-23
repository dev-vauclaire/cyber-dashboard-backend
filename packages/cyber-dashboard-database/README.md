# Package database

`packages/database` centralise la source de verite de la base partagee par les
applications du monorepo.

Sous-dossiers :

- `models/` : modeles SQLAlchemy de reference du schema ;
- `db/` : primitives de connexion PostgreSQL et builders partages ;
- `repositories/` : acces aux donnees reutilisables par plusieurs apps.

Principes de fonctionnement :

- les modeles du schema sont definis ici avant toute migration Alembic ;
- les repositories de ce package ne doivent pas dependre d'une application
  concrete ;
- ils peuvent couvrir aussi bien des lectures API que des ecritures techniques
  pour les workers ;
- chaque app peut exposer une facade locale vers ces repositories si elle veut
  garder un espace de noms stable.

Regle importante :

- toute evolution de schema doit d'abord etre refletee dans `models/`, puis
  portee dans `alembic/`.
