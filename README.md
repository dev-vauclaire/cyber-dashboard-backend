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
Cette page sert de point d'entrée aux nouveaux développeurs qui veulent
contribuer au backend Cyber Dashboard.

## Prerequis

Avant de configurer le projet, installez les outils suivants :

| Outil | Usage |
| --- | --- |
| Python 3.12 | Version Python attendue par le workspace |
| `uv` | Gestion des dépendances, du lockfile et des environnements virtuels |
| GNU Make | Raccourcis de lancement des applications et des hooks |
| Docker | Build et execution des images applicatives |
| Docker Compose | Orchestration locale (`docker compose` ou `docker-compose`) |
| Syft | Generation du SBOM de `uv.lock` pendant le hook de sécurité |
| Grype | Scan de vulnérabilités du SBOM généré par Syft |

Vérifiez que les binaires sont disponibles dans votre shell :

```bash
python --version
uv --version
make --version
docker --version
docker compose version
# ou, selon votre installation :
docker-compose --version
syft version
grype version
```

## Configuration de l'environnement de developpement

Ce dépôt utilise [`uv`](https://docs.astral.sh/uv/getting-started/installation/)
pour gérer les dépendances, le lockfile et l'environnement virtuel.

Placez-vous à la racine du monorepo et installez les dépendances verrouillées :

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

Pour lancer les applications en mode développement, utilisez la cible `make`
qui correspond au service sur lequel vous travaillez :

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

## Lancer les tests unitaires : PAS ENCORE IMPLEMENTÉ

Les tests unitaires se lancent avec `unittest` via `uv`.
Depuis la racine du monorepo :

```bash
# Tests du script de migration
uv run python -m unittest scripts.tests.test_migrate

# Tests de l'API
uv run --directory apps/cyber_dashboard_api python -m unittest tests.test_all

# Tests du scheduler
uv run --directory apps/cyber_dashboard_scheduler \
  python -m unittest discover -s tests -t .

# Tests du service de correlation d'IP
uv run --directory apps/cyber_dashboard_common_ip python -m unittest tests.test_all
```

## Lancer les hooks de qualité et de sécurité

Le projet utilise [`pre-commit`](https://pre-commit.com/)
pour exécuter des hooks :

- Linting
- Formatage
- Secrets detection
- SCA (Software Composition Analysis)
- SAST (Static Application Security Testing)

La configuration se trouve dans `.pre-commit-config.yaml` à la racine du projet.

Pour lancer les hooks de qualité sur tous les fichiers du projet,
vous pouvez utiliser la commande suivante :

```bash
uv run pre-commit run --all-files
```

Pour activer les hooks avant chaque commit,
vous pouvez utiliser la commande suivante :

```bash
uv run pre-commit install
```

Pour mettre à jour les versions des hooks
déclarés dans `.pre-commit-config.yaml` :

```bash
uv run pre-commit autoupdate
```

Les hooks actuellement configurés sont :
<!-- markdownlint-disable MD013 -->
| Hook | Type de vérification |
| --- | --- |
| `pre-commit-hooks` | Fins de lignes, espaces, YAML/TOML/JSON, conflits de merge, clés privées |
| `markdownlint` | Lint et auto-correction des fichiers Markdown |
| `black` | Formatage Python |
| `ruff` | Lint Python avec auto-correction |
| `gitleaks` | Détection de secrets |
| `uv-lock-sbom-grype` | SBOM `uv.lock` avec Syft puis scan de vulnérabilités avec Grype |
| `semgrep` | SAST Python et règles `security-audit` |
<!-- markdownlint-enable MD013 -->
Les tests unitaires seront lancés par `pre-commit` mais
actuellement ce n'est pas encore implémenté.

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

TODO : Ajouter le processus d'analyse de sécurité des images avec Syft, Grype et VEX

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
