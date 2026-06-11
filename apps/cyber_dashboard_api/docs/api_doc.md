# Documentation API

Ce document recense les endpoints exposes par `apps/cyber_dashboard_api`.

Base URL locale par defaut :

```text
http://127.0.0.1:8000
```

Conventions generales :

- les chemins canoniques sont declares sans slash final ;
- les reponses d'erreur suivent l'enveloppe `{ "error": { ... } }` ;
- les timestamps sont exposes en ISO 8601 ;
- les routes de configuration n'exposent jamais les secrets en clair ni chiffres.

## Format d'erreur

```json
{
  "error": {
    "code": "validation_error",
    "message": "Invalid request parameters",
    "details": [
      {
        "location": "query.page",
        "message": "Input should be greater than or equal to 1",
        "type": "greater_than_equal",
        "input": 0
      }
    ]
  }
}
```

Statuts frequents :

- `200 OK` : succes standard
- `201 Created` : creation de ressource
- `204 No Content` : suppression sans body
- `400 Bad Request` : erreur metier ou plage/filtre invalide
- `404 Not Found` : ressource absente
- `409 Conflict` : conflit logique en base
- `422 Unprocessable Entity` : validation FastAPI/Pydantic
- `503 Service Unavailable` : secret indisponible ou integration externe indisponible

## Endpoints systeme

- `GET /health`
  Retourne `{"status":"ok"}` si l'application demarre correctement.

## Dashboard

- `GET /api/dashboard/overview`
  Retourne :
  - `total_attacks`
  - `total_common_ip_alerts`
  - `total_active_sources`
  - `total_inactive_sources`

## Sources

- `GET /api/sources/inventory`
  Retourne l'inventaire agrege par type de capteur.
- `GET /api/sources`
  Retourne la liste des sources individuelles.
  Champs principaux :
  - `source_id`
  - `source_name`
  - `site_url`
  - `is_active`
  - `created_at`
  - `sensor_type_code`
  - `sensor_type_label`
  - `color`
- `PATCH /api/sources/{source_id}/name`
  Body :
  ```json
  { "source_name": "OGO Paris PROD" }
  ```
- `PATCH /api/sources/{source_id}/is_active`
  Body :
  ```json
  { "is_active": false }
  ```
- `PATCH /api/sources/{source_id}/color`
  Body :
  ```json
  { "color": "#2563EB" }
  ```

## Alertes IP communes

- `GET /api/alerts/common-ips`
  Query params :
  - `page`
  - `limit`
  - `source_id` repetable
  - `from`
  - `to`
  - `min_distinct_source_count`
- `GET /api/alerts/common-ips/{alert_id}`
  Retourne :
  - `attacker_ip`
  - `sources[]`
    Champs par source :
    - `source_id`
    - `source_name`
    - `first_seen_at`
    - `last_seen_at`
    - `hit_count`

## Attaques

- `GET /api/attacks`
  Query params :
  - `page`
  - `page_size`
  - `sensor_type`
  - `source_id`
  - `from`
  - `to`
  - `attack_type`

  Reponse :
  - `pagination`
  - `items[]`
    Champs principaux :
    - `id`
    - `attacker_ip`
    - `occurred_at`
    - `collected_at`
    - `attack_type`
    - `source_id`
    - `source_name`
    - `sensor_type_code`

## Statistiques d'attaques

- `GET /api/stats/attacks/summary`
  Query params : `from`, `to`
- `GET /api/stats/attacks/by-source`
  Query params : `from`, `to`
- `GET /api/stats/attacks/by-source-timeseries`
  Query params : `from`, `to`
  Particularite :
  - `bucket="day"`
  - `bucket_starts_utc` expose des instants UTC correspondant aux debuts de jour Paris
  - `series[].data` suit cet ordre de buckets
- `GET /api/stats/attacks/by-type`
  Query params : `from`, `to`

## Configurations CTI

- `GET /api/cti-config`
- `GET /api/cti-config/{code}`
- `PATCH /api/cti-config/{code}`
  Body possible :
  ```json
  {
    "label": "RDAP / WHOIS",
    "api_key": "optional-secret"
  }
  ```
- `POST /api/cti-config/{code}/activate`
- `POST /api/cti-config/{code}/deactivate`
- `DELETE /api/cti-config/{code}/api-key`

Champs publics principaux :

- `code`
- `label`
- `is_key_required`
- `is_active`
- `has_api_key`
- `api_key_hint`
- `last_validation_status`
- `last_validation_at`
- `last_validation_error`

## Enrichissement CTI

Chaque route attend `ip_address` en query string.

- `GET /api/cti-enrichment/abuseipdb`
  Query param optionnel : `max_age_in_days`
- `GET /api/cti-enrichment/ipdata`
- `GET /api/cti-enrichment/greynoise`
- `GET /api/cti-enrichment/rdap`
- `GET /api/cti-enrichment/shodan`
- `GET /api/cti-enrichment/virustotal`

Ces routes dependent de la configuration CTI active et, selon le provider, d'une cle valide.

## Configuration SMTP

- `GET /api/smtp-config`
- `PATCH /api/smtp-config`
- `PUT /api/smtp-config`
- `POST /api/smtp-config/activate`
- `POST /api/smtp-config/deactivate`
- `DELETE /api/smtp-config/password`

Le body de `PATCH`/`PUT` accepte notamment :

- `smtp_host`
- `smtp_port`
- `smtp_user`
- `smtp_password`
- `smtp_from`
- `smtp_from_name`

## Configurations de collecteurs d'attaques

- `GET /api/attacks-collector-config`
- `GET /api/attacks-collector-config/{id}`
- `POST /api/attacks-collector-config`
- `PATCH /api/attacks-collector-config/{id}`
- `DELETE /api/attacks-collector-config/{id}`
- `POST /api/attacks-collector-config/{id}/activate`
- `POST /api/attacks-collector-config/{id}/deactivate`
- `DELETE /api/attacks-collector-config/{id}/api-key`
- `DELETE /api/attacks-collector-config/{id}/email`
- `POST /api/attacks-collector-config/{id}/request-inventory`

Body de creation :

```json
{
  "name": "OGO prod",
  "collector_type": "ogo",
  "api_key": "optional-secret",
  "email": "optional@example.org",
  "is_active": false
}
```

Body de patch :

```json
{
  "name": "OGO prod updated",
  "collector_type": "ogo",
  "api_key": "optional-secret",
  "email": "optional@example.org"
}
```

## Retention

- `GET /api/retention-policies`
- `GET /api/retention-policies/{target_table}`
- `PATCH /api/retention-policies/{target_table}`

Body de patch :

```json
{
  "retention_days": 90,
  "is_active": true
}
```

## Tests rapides

Voir [testing.md](./testing.md) pour :

- les tests unitaires `unittest`
- le smoke test HTTP sur localhost
- les options pour couvrir aussi les routes mutables, externes et destructives
