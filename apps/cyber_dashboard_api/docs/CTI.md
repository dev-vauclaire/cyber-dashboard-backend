# Documentation technique : enrichissements CTI

Ce document décrit la logique CTI actuellement implémentée dans `cyber-dashboard-api`.
Il couvre :

- les routes REST d'enrichissement CTI
- les prérequis côté configuration
- les champs projetés pour chaque provider
- les règles de robustesse appliquées quand des champs externes sont absents

## Vue d'ensemble

Les enrichissements CTI sont exposés sous le préfixe :

```bash
/api/cti-enrichment
```

Routes actuellement disponibles :

- `GET /api/cti-enrichment/abuseipdb`
- `GET /api/cti-enrichment/ipdata`
- `GET /api/cti-enrichment/greynoise`
- `GET /api/cti-enrichment/rdap`
- `GET /api/cti-enrichment/shodan`
- `GET /api/cti-enrichment/virustotal`

Toutes les routes attendent un paramètre `ip_address` au format IPv4 ou IPv6.

Exemple :

```bash
curl "http://127.0.0.1:8000/api/cti-enrichment/shodan?ip_address=8.8.8.8"
```

## Prérequis de configuration

Avant d'utiliser un provider CTI :

- sa configuration doit exister dans `cti_config`
- la configuration doit être `is_active = true`
- si `is_key_required = true`, une clé API valide doit être stockée

Cas particulier :

- `rdap` ne nécessite pas de clé API

Si un provider est inactif, l'API renvoie une erreur métier `cti_provider_inactive`.
Si une clé est requise mais absente, l'API renvoie `cti_provider_not_configured`.

## Règles communes de robustesse

L'API applique les règles suivantes pour tous les enrichissements :

- si le payload racine n'est pas un objet JSON, la réponse est rejetée avec `cti_enrichment_invalid_response`
- si des sous-champs attendus sont absents, l'API retourne des valeurs par défaut au lieu d'échouer
- les erreurs réseau, timeout, DNS, authentification ou indisponibilité externe sont normalisées en `cti_enrichment_unavailable`
- l'adresse IP renvoyée retombe sur l'IP demandée si le provider ne fournit pas de champ IP exploitable

Valeurs par défaut courantes :

- chaîne absente : `null`
- liste absente : `[]`
- booléen absent : `false`
- nombre absent : `0`
- date absente : `null`

## AbuseIPDB

Code provider :

```text
abuseipdb
```

Documentation officielle :

```text
https://docs.abuseipdb.com/#check-endpoint
```

Route externe utilisée :

```bash
https://api.abuseipdb.com/api/v2/check
```

Route API :

```bash
GET /api/cti-enrichment/abuseipdb?ip_address={ip}&max_age_in_days=30
```

Paramètres :

- `ip_address` : IP à enrichir
- `max_age_in_days` : entier entre `1` et `365`

Champs renvoyés par l'API :

- `ip_address`
- `abuse_confidence_score`
- `country_code`
- `isp`
- `last_reported_at`
- `total_reports`
- `category_percentages`

Mapping principal :

- `data.ipAddress` -> `ip_address`
- `data.abuseConfidenceScore` -> `abuse_confidence_score`
- `data.countryCode` -> `country_code`
- `data.isp` -> `isp`
- `data.lastReportedAt` -> `last_reported_at`
- `data.totalReports` -> `total_reports`

Règle spécifique :

- `category_percentages` est calculé à partir des catégories présentes dans `data.reports[*].categories`
- le pourcentage est calculé par rapport à `total_reports`
- les catégories sont dédupliquées à l'intérieur d'un même rapport avant agrégation

Documentation catégories :

```text
https://www.abuseipdb.com/categories
```

## VirusTotal

Code provider :

```text
virustotal
```

Documentation officielle :

```text
https://docs.virustotal.com/reference/ip-info
```

Route externe utilisée :

```bash
https://www.virustotal.com/api/v3/ip_addresses/{ip_address}
```

Route API :

```bash
GET /api/cti-enrichment/virustotal?ip_address={ip}
```

Champs renvoyés par l'API :

- `ip_address`
- `reputation`
- `country_code`
- `as_owner`
- `last_analysis_stats`

Mapping principal :

- `data.id` -> `ip_address`
- `data.attributes.reputation` -> `reputation`
- `data.attributes.country` -> `country_code`
- `data.attributes.as_owner` -> `as_owner`
- `data.attributes.last_analysis_stats` -> `last_analysis_stats`

Sous-champs de `last_analysis_stats` :

- `malicious`
- `suspicious`
- `harmless`
- `undetected`
- `timeout`

## IPdata

Code provider :

```text
ipdata
```

Documentation officielle :

```text
https://docs.ipdata.co/docs/getting-started
```

Route externe utilisée :

```bash
https://api.ipdata.co/{ip_address}?api-key={your_api_key}
```

Route API :

```bash
GET /api/cti-enrichment/ipdata?ip_address={ip}
```

Champs renvoyés par l'API :

- `ip_address`
- `country_name`
- `asn_name`
- `is_threat`

Mapping principal :

- `ip` -> `ip_address`
- `country_name` -> `country_name`
- `asn.name` -> `asn_name`
- `threat.is_threat` -> `is_threat`

## RDAP

Code provider :

```text
rdap
```

Documentation officielle :

```text
https://about.rdap.org/
```

Route externe utilisée :

```bash
https://rdap.org/ip/{ip_address}
```

Route API :

```bash
GET /api/cti-enrichment/rdap?ip_address={ip}
```

Champs renvoyés par l'API :

- `ip_address`
- `name`
- `country`
- `abuse_contact_email`
- `start_address`
- `end_address`

Logique de mapping :

- `name` provient de `payload.name`
- `country` est extrait de l'entité ayant le rôle `registrant`
- `abuse_contact_email` est extrait de la première entité imbriquée ayant le rôle `abuse`
- `start_address` provient de `startAddress`
- `end_address` provient de `endAddress`

Règle d'extraction du pays :

- on cherche une entrée `adr` dans `vcardArray`
- on lit `parameters.label`
- on découpe la valeur sur les retours à la ligne
- on conserve la dernière ligne comme pays

Règle d'extraction de l'email abuse :

- on cherche une entrée `email` dans le `vcardArray` de l'entité abuse
- on retourne la valeur texte associée

## GreyNoise

Code provider :

```text
greynoise
```

Documentation officielle :

```text
https://docs.greynoise.io/reference/getcommunityip
```

Route externe utilisée :

```bash
https://api.greynoise.io/v3/community/{ip}
```

Route API :

```bash
GET /api/cti-enrichment/greynoise?ip_address={ip}
```

Champs renvoyés par l'API :

- `ip_address`
- `classification`
- `name`
- `link`
- `last_seen`

Mapping principal :

- `ip` -> `ip_address`
- `classification` -> `classification`
- `name` -> `name`
- `link` -> `link`
- `last_seen` -> `last_seen`

Exemple de payload source :

```json
{
  "ip": "71.6.135.131",
  "noise": true,
  "riot": false,
  "classification": "benign",
  "name": "Shodan.io",
  "link": "https://viz.greynoise.io/ip/71.6.135.131",
  "last_seen": "2026-06-10",
  "message": "Success"
}
```

Note de validation :

- l'activation valide la clé avec `GET https://api.greynoise.io/ping`
- l'endpoint Community n'est utilisé que pour l'enrichissement, car il accepte aussi les requêtes non authentifiées

## Shodan

Code provider :

```text
shodan
```

Documentation officielle :

```text
https://developer.shodan.io/api
```

Route externe utilisée :

```bash
https://api.shodan.io/shodan/host/{ip_address}?key={your_api_key}
```

Note de validation :

- l'activation valide la clé avec `GET https://api.shodan.io/api-info?key={your_api_key}`
- l'endpoint hôte n'est utilisé que pour l'enrichissement, car il accepte aussi les requêtes non authentifiées

Route API :

```bash
GET /api/cti-enrichment/shodan?ip_address={ip}
```

Champs renvoyés par l'API :

- `ip_address`
- `organization`
- `asn`
- `country_name`
- `hostnames`
- `exposed_ports`
- `services`
- `known_vulnerabilities_count`
- `vulnerabilities`
- `last_observed_at`

Mapping principal :

- `ip_str` -> `ip_address`
- `org` -> `organization`
- `asn` -> `asn`
- `country_name` -> `country_name`
- `hostnames` -> `hostnames`

Logique sur les ports exposés :

- on boucle sur `data[*]`
- on lit `port`
- on lit `transport`, avec fallback sur `tcp`
- on produit une valeur de type `53/udp` ou `443/tcp`
- les doublons sont supprimés en conservant l'ordre d'apparition

Logique sur les services :

- si `_shodan.module` contient `dns` -> `DNS`
- sinon s'il contient `https` -> `HTTPS`
- sinon s'il contient `http` -> `HTTP`
- sinon si `ssl` existe -> `TLS`
- sinon on conserve le nom du module Shodan
- les doublons sont supprimés en conservant l'ordre d'apparition

Logique sur les vulnérabilités :

- on collecte les clés de `payload.vulns`
- on collecte `item.vulns` pour chaque entrée de `data`
- on collecte `item.opts.vulns` pour chaque entrée de `data`
- les doublons sont supprimés en conservant l'ordre d'apparition
- `known_vulnerabilities_count` est la taille de la liste dédupliquée

Logique sur la dernière observation :

- on collecte `last_update`
- on collecte chaque `item.timestamp`
- on parse les dates ISO 8601
- on conserve la date la plus récente dans `last_observed_at`

## Exemple d'erreurs normalisées

Exemple d'erreur provider inactif :

```json
{
  "error": {
    "code": "cti_provider_inactive",
    "message": "CTI provider 'shodan' is not active"
  }
}
```

Exemple d'erreur provider indisponible :

```json
{
  "error": {
    "code": "cti_enrichment_unavailable",
    "message": "Shodan service is unavailable"
  }
}
```

Exemple d'erreur de payload externe invalide :

```json
{
  "error": {
    "code": "cti_enrichment_invalid_response",
    "message": "Shodan returned an unexpected response"
  }
}
```
