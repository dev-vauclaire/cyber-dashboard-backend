# CYBER DASHBOARD COMMON IP

Worker de correlation charge de detecter les adresses IP vues sur plusieurs sources.

Dans le monorepo, `common_ip` garde sa logique metier locale mais s'appuie desormais sur :

- `packages/database/db` pour la connexion PostgreSQL partagee ;
- `packages/database/repositories` pour les acces SQL communs au correlateur ;
- `packages/database/models` comme source de verite du schema utilise par les tests d'integration.

## Role de l'application

Le worker :

- lit les attaques en statut `pending` ;
- reclamme des lots avec `FOR UPDATE SKIP LOCKED` ;
- maintient un registre memoire minimal des IP deja vues ;
- cree ou met a jour `common_ip_alerts` et `common_ip_alert_sources` ;
- repasse une attaque en `pending` si son traitement echoue.

Le service reste volontairement simple : pas d'API HTTP, pas d'integration externe, uniquement la boucle de correlation.

## Structure utile

```text
apps/common_ip/
├── common_ip_correlator/
│   ├── config/             # lecture des variables d'environnement
│   ├── db/                 # facade locale vers packages.database.db
│   ├── domain/             # objets metier du correlateur
│   ├── repositories/       # wrappers locaux vers les repositories partages
│   ├── services/           # boucle de correlation et chargement d'etat
│   ├── _runtime.py         # bootstrap du PYTHONPATH pour le monorepo
│   └── main.py             # point d'entree du worker
├── tests/
├── Dockerfile
└── requirements.txt
```

## Variables d'environnement

Variables PostgreSQL recommandees :

- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`

Variables du worker :

- `CORRELATOR_BATCH_SIZE`
- `CORRELATOR_POLL_INTERVAL_SECONDS`
- `CORRELATOR_LOG_LEVEL`
- `CORRELATOR_COMPUTE_AVERAGE_PROCESSING_TIME`

Les anciens alias `CORRELATOR_DB_*`, `POSTGRES_*` et `PG*` restent supportes pour faciliter la transition.

Le fichier [.env.example](./.env.example) sert de base.

## Demarrage local

Depuis `apps/common_ip` :

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m common_ip_correlator.main
```

Le bootstrap `common_ip_correlator/_runtime.py` ajoute automatiquement la racine `cyber-dashboard-backend` au `PYTHONPATH`, ce qui permet aux imports `packages.*` de fonctionner meme si l'application est lancee depuis son sous-dossier.

## Boucle de traitement

Au demarrage :

1. chargement de la configuration ;
2. creation de la connexion PostgreSQL partagee ;
3. remise en `pending` des attaques eventuellement laissees en `processing` ;
4. reconstruction du registre memoire a partir des attaques deja `completed`.

Ensuite, chaque cycle :

1. reclame un lot d'attaques `pending` ;
2. traite chaque attaque dans une transaction courte ;
3. cree ou met a jour les alertes si l'IP est vue sur plusieurs sources ;
4. attend `CORRELATOR_POLL_INTERVAL_SECONDS` si aucun lot n'est disponible.

## Tests

Lancer toute la suite :

```bash
cd apps/common_ip
. .venv/bin/activate
python -m unittest tests.test_all
```

Fichiers de tests :

- `test_domain.py` : IP et registre memoire
- `test_batch_processing_time_tracker.py` : mesure de performance par lot
- `test_correlator.py` : orchestration metier du service principal
- `test_repositories.py` : mapping des wrappers locaux vers le SQL partage
- `test_postgres_integration.py` : verification sur PostgreSQL avec le schema SQLAlchemy partage

## Docker

Les builds Docker doivent partir de la racine du monorepo `cyber-dashboard-backend`, car l'image depend aussi de `packages/`.

Build :

```bash
docker build -f apps/common_ip/Dockerfile -t cyber-dashboard-common-ip:prod .
```

Run :

```bash
docker run --rm --env-file apps/common_ip/.env cyber-dashboard-common-ip:prod
```
