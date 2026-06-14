# cyber-dashboard-scheduler

Scheduler V2 du projet `cyber-dashboard`.

Cette application porte l'inventaire des sources et la collecte des attaques à partir de `attacks_collector_config`.

## Variables d'environnement

Variables obligatoires :

- `DB_HOST` : hôte PostgreSQL
- `DB_PORT` : port PostgreSQL
- `DB_NAME` : nom de la base
- `DB_USER` : utilisateur PostgreSQL
- `DB_PASSWORD` : mot de passe PostgreSQL
- `LIMIT_REQUEST_PER_DAY` : nombre maximal de cycles scheduler par jour
- `LOG_LEVEL` : niveau de logs parmi `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`
- `OGO_BASE_URL` : URL racine de l'API OGO V2
- `SERENICITY_BASE_URL` : URL racine de l'API Serenicity

Variables optionnelles :

- `HTTP_TIMEOUT_SECONDS` : timeout réseau par requête HTTP, défaut `10`
- `POLL_SAFETY_WINDOW_SECONDS` : fenêtre de sécurité retranchée au `last_poll_at`, défaut `300`
- `CYBER_DASHBOARD_SECRET_KEY_FILE` : chemin vers la clé maître de chiffrement
- `CYBER_DASHBOARD_SECRET_KEY` : clé maître de chiffrement en variable d'environnement

Un exemple est fourni dans [.env.example](./.env.example).

## Flow

Le flow actuel du scheduler est le suivant :

1. Chargement de la configuration et initialisation des logs.
2. Vérification de la connexion PostgreSQL.
3. À chaque cycle, lecture des lignes `attacks_collector_config` où `is_active = TRUE` et `inventory_requested = TRUE`.
4. Déchiffrement des secrets stockés en base.
5. Inventaire OGO via `GET /v2/organizations` puis `GET /v2/organizations/{code}/sites`.
6. Inventaire Serenicity via `GET /api/v1/sensors` et `GET /api/v1/lurios`.
7. Mise à jour des tables `sources`, `ogo_sources`, `serenicity_sources` et `scheduler_state`.
8. Si une configuration se termine sans erreur, remise de `inventory_requested` à `FALSE`.
9. Collecte OGO via `GET /v2/organizations/{code}/journal`.
10. Collecte Serenicity des capteurs via `GET /api/v1/sensors/{sensor_id}/flux`.
11. Collecte Serenicity des lurios via `GET /api/v1/lurios/{lurio_id}/reports`.
12. Insertion des attaques dans `attacks` avec génération d'un `deduplication_id` stable et mise à jour de `scheduler_state.last_poll_at`.

## Mode de lancement

Pré-requis :

1. Créer un environnement virtuel Python.
2. Installer les dépendances avec `pip install -r requirements.txt`.
3. Copier `.env.example` vers `.env` et renseigner les variables.
4. Vérifier que la clé maître de chiffrement utilisée pour l'API est aussi disponible pour le scheduler.

Commande locale de démarrage :

```bash
cd apps/scheduler
python3 -m cyber_dashboard_scheduler.main
```

Exemple complet :

```bash
cd apps/scheduler
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 -m cyber_dashboard_scheduler.main
```

## Stratégie d'inventaire

- L'inventaire est exécuté de manière périodique à chaque cycle.
- Une source appartient au plus à une seule `attacks_collector_config` via `sources.attacks_collector_config_id`.
- Si une source historisee sans configuration est redetectee, le scheduler peut la rattacher a la configuration courante.
- Cote OGO, les codes d'organisation visibles pour un domaine sont stockes directement dans `ogo_sources.organization_codes`.
- Si une source disparait d'un inventaire, elle est simplement desactivee mais conserve son rattachement et son historique.
- Chaque source conserve son historique dans `scheduler_state`.

La collecte d'attaques s'appuie sur les sources déjà inventoriées et sur les secrets chiffrés stockés en base.

## Structure

```text
cyber_dashboard_scheduler/
├── clients/
├── config/
├── db/
├── models/
├── services/
│   ├── collection/
│   └── normalization/
├── utils/
└── main.py
```

- `clients` : clients HTTP des APIs externes
- `config` : chargement des variables d'environnement
- `db` : façade locale vers `packages/database/db`
- `models` : modèles internes du scheduler
- `services` : orchestration métier, inventaire et runtime
- `services/collection` : collecteurs d'attaques et helpers de collecte
- `services/normalization` : normalisation des payloads sources et attaques
- `utils` : fonctions utilitaires
- `main.py` : point d'entrée
