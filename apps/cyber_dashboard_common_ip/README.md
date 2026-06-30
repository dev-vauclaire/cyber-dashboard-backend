# Cyber Dashboard Common IP

Worker de correlation charge de detecter les adresses IP observees sur plusieurs
sources. La distribution `cyber-dashboard-common-ip` fournit le module
`cyber_dashboard_common_ip` et la commande `cyber-common-ip`.

Le worker s'appuie sur `cyber_dashboard_database` pour la connexion, le schema
SQLAlchemy et les repositories partages.

## Fonctionnement

Le service :

1. charge son etat depuis PostgreSQL ;
2. reclame les attaques `pending` par lots avec `FOR UPDATE SKIP LOCKED` ;
3. maintient un registre memoire minimal des IP deja vues ;
4. cree ou met a jour `common_ip_alerts` et `common_ip_alert_sources` ;
5. remet une attaque en `pending` si son traitement echoue.

## Structure

```text
apps/cyber_dashboard_common_ip/
├── src/cyber_dashboard_common_ip/
│   ├── config/
│   ├── db/
│   ├── domain/
│   ├── repositories/
│   ├── services/
│   └── main.py
├── tests/
├── Dockerfile
└── pyproject.toml
```

## Demarrage local

Depuis la racine :

```bash
uv sync --all-packages --locked
cp apps/cyber_dashboard_common_ip/.env.example \
  apps/cyber_dashboard_common_ip/.env
make common-ip
```

Commande equivalente :

```bash
uv run --package cyber-dashboard-common-ip cyber-common-ip
```

L'application charge automatiquement
`apps/cyber_dashboard_common_ip/.env`.

## Variables d'environnement

Connexion PostgreSQL :

- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`.

Comportement du worker :

- `CORRELATOR_BATCH_SIZE` ;
- `CORRELATOR_POLL_INTERVAL_SECONDS` ;
- `CORRELATOR_LOG_LEVEL` ;
- `CORRELATOR_COMPUTE_AVERAGE_PROCESSING_TIME`.

Le fichier [.env.example](./.env.example) contient les valeurs de depart. Les
anciens alias `CORRELATOR_DB_*`, `POSTGRES_*` et `PG*` restent acceptes pendant
la transition.

## Tests

```bash
uv run --directory apps/cyber_dashboard_common_ip python -m unittest tests.test_all
```

Le test d'integration PostgreSQL est ignore lorsqu'aucune base de test n'est
configuree.

## Docker

Depuis la racine :

```bash
docker build \
  -f apps/cyber_dashboard_common_ip/Dockerfile \
  -t cyber-dashboard-common-ip:prod .

docker run --rm \
  --env-file apps/cyber_dashboard_common_ip/.env \
  cyber-dashboard-common-ip:prod
```
