# Cyber-dashboard-backend

Ce monorepo contient les applications backend du projet Cyber Dashboard.
Elle comporte trois applications une API REST FastAPI,
un scheduler pour la collecte et la planification,
et un service de correlation d'IP.

## Architecture du depot

```text
cyber-dashboard-backend/
├── alembic/                               # Migrations de schema
├── apps/                                  # Applications du monorepo
│   ├── cyber_dashboard_api/               # API REST FastAPI
│   ├── cyber_dashboard_common_ip/         # Correlation d'IP
│   └── cyber_dashboard_scheduler/         # Collecte et planification
├── packages/                              # Packages partages
│   ├── cyber_dashboard_common_tools/      # Outils techniques partages
│   └── cyber_dashboard_database/          # Sources de vérité de la base de données
├── scripts/                               # Script de migrations
├── pyproject.toml                         # Configuration du workspace uv
└── uv.lock
```

Chaque application et package a sa propre documentation dans son dossier respectif.

## Installation de l'environnement de developpement

Ce dépot utilise l'outil [`uv`](https://docs.astral.sh/uv/getting-started/installation/)
pour la gestion des dépendances,
des versions de python et des environnements virtuels.

Pour installer l'environnement de developpement, vous devrez installer
[`uv`](https://docs.astral.sh/uv/getting-started/installation/) :

Ensuite, placez-vous à la racine du monorepo et lancez la commande suivante :

```bash
# Créer un environnement virtuel python avec toutes les dépendances requises (uv.lock)
uv sync --all-packages --locked
```

Vérifiez qu'un environnement virtuel a bien été créé dans le dossier `.venv`.

### Configuration des variables d'environnement

Chaque application lit un fichier `.env` local. Les fichiers exemples sont
situes dans les trois dossiers d'application.
Basez-vous sur ces fichiers pour créer vos propres fichiers `.env` locaux.
<!-- markdownlint-disable MD013 -->
```bash
# Créer des fichiers .env locaux à partir des exemples
cp apps/cyber_dashboard_api/.env.example apps/cyber_dashboard_api/.env
cp apps/cyber_dashboard_scheduler/.env.example apps/cyber_dashboard_scheduler/.env
cp apps/cyber_dashboard_common_ip/.env.example apps/cyber_dashboard_common_ip/.env
```

> Pour chaque application, vous trouverez plus de détails sur leurs variables d'environnement dans leurs README respectifs.
<!-- markdownlint-enable MD013 -->
## Lancer les applications en mode développement

Pour lancer les applications en mode développement dépendament de ce
sur quoi vous travaillez, vous pouvez utiliser les commandes `make` suivantes :

```bash
# Lance l'API
make api
# Lance le scheduler
make scheduler
# Lance la correlation d'IP
make common-ip
# Lance les migrations
make migrate
```

## Lancer hooks de qualité

Pour ce qui est des hooks de qualités, le projet utilise
[`pre-commit`](https://pre-commit.com/) pour executer les linters et les tests unitaires.
Vous pouvez voir la liste des hooks dans le fichier
`.pre-commit-config.yaml` à la racine du projet.

Pour lancer les hooks de qualité sur tous les fichiers du projet,
vous pouvez utiliser la commande suivante :

```bash
make lint
```

Pour activer les hooks avant chaque commit,
vous pouvez utiliser la commande suivante :

```bash
make active_lint_on_commit
```

## Lancer les tests unitaires et les hooks de qualite

TODO :
`make test_all`, `make test_<application>` `make test_<package>`

## Conteneurisation avec Docker

### Build des images

<!-- markdownlint-disable MD013 -->

| Cible | Build depuis la racine |
| --- | --- |
| API | `docker build -f apps/cyber_dashboard_api/Dockerfile -t cyber-dashboard-api:prod .` |
| Scheduler | `docker build -f apps/cyber_dashboard_scheduler/Dockerfile -t cyber-dashboard-scheduler:prod .` |
| Common IP | `docker build -f apps/cyber_dashboard_common_ip/Dockerfile -t cyber-dashboard-common-ip:prod .` |
| Migrations | `docker build -f Dockerfile.migrate -t cyber-dashboard-migrate:prod .` |

> Remarque : Placer vous dans le dossier racine du projet pour lancer les commandes de build.

### Exécuter les conteneurs

Pour que les conteneurs puissent communiquer entre eux vous pouvez créer un réseau docker et les lancer sur ce réseau.

Créer un réseau docker nommé `cyber-dashboard-network` :

```bash
docker network create cyber-dashboard-network
```

Ensuite, vous pouvez lancer les conteneurs dans un même réseau avec le paramètre `--network` :

| Cible | Execution |
| --- | --- |
| API | `docker run --rm -p 8000:8000 --env-file apps/cyber_dashboard_api/.env --network cyber-dashboard-network cyber-dashboard-api:prod` |
| Scheduler | `docker run --rm --env-file apps/cyber_dashboard_scheduler/.env --network cyber-dashboard-network cyber-dashboard-scheduler:prod` |
| Common IP | `docker run --rm --env-file apps/cyber_dashboard_common_ip/.env --network cyber-dashboard-network cyber-dashboard-common-ip:prod` |
| Migrations | `docker run --rm -e DATABASE_URL=postgresql+psycopg://user:password@host/database --network cyber-dashboard-network cyber-dashboard-migrate:prod` |

> Remarque : Vous devez avoir créé vos propres fichiers `.env` pour chaque application
<!-- markdownlint-enable MD013 -->

## Documentation des sous-projets

| Cible | Lien vers la documentation |
| --- | --- |
| API | [README](apps/cyber_dashboard_api/README.md) |
| Scheduler | [README](apps/cyber_dashboard_scheduler/README.md) |
| Common IP | [README](apps/cyber_dashboard_common_ip/README.md) |
| Migrations | [Migrations Alembic](#migrations-alembic) |
| Outils communs | [README](packages/cyber_dashboard_common_tools/README.md) |
| Base de données | [README](packages/cyber_dashboard_database/README.md) |

## Migrations Alembic

Le script `scripts/migrate.py` choisit le traitement selon l'etat de la base :

1. une base vide est migree avec `alembic upgrade head` ;
2. une base V1 legacy est marquee a la revision `6d98af97a0e5`, puis migree ;
3. une base deja versionnee est migree jusqu'a `head` ;
4. un schema inconnu provoque un arret de securite.

Variables disponibles :

- `DATABASE_URL`, obligatoire ;
- `V1_BASELINE_REVISION`, optionnelle ;
- `DATABASE_WAIT_TIMEOUT_SECONDS`, optionnelle ;
- `DATABASE_WAIT_POLL_SECONDS`, optionnelle.
