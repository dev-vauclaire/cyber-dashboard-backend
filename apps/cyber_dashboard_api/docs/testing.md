# Tests

Ce document decrit la strategie de test de `cyber_dashboard_api`.

## 1. Tests unitaires

La suite principale est basee sur `unittest`.

Commande :

```bash
cd apps/cyber_dashboard_api
. .venv/bin/activate
python -m unittest tests.test_all
```

Le lanceur global assemble les suites par domaine :

- `tests/attacks/`
- `tests/alerts/`
- `tests/attacks_collector_config/`
- `tests/cti_config/`
- `tests/cti_enrichment/`
- `tests/dashboard/`
- `tests/health/`
- `tests/retention_policies/`
- `tests/smtp_config/`
- `tests/sources/`
- `tests/stats/`

Objectif :

- tester les services ;
- tester les routes ;
- valider les cas d'erreur metier ;
- verifier les shapes de reponse.

## 2. Smoke test HTTP localhost

Le script `scripts/test_localhost_routes.py` appelle l'API reelle sur `localhost`.

Prerequis :

1. l'API doit etre demarree ;
2. la base doit etre joignable ;
3. certaines routes externes demandent des configurations actives et valides.

Commande minimale :

```bash
cd apps/cyber_dashboard_api
. .venv/bin/activate
python scripts/test_localhost_routes.py
```

Cette commande :

- teste les routes de lecture et de sante ;
- produit un rapport `PASS` / `FAIL` / `SKIP` ;
- retourne un code de sortie `1` si au moins un test est en echec.

### Ajouter le rapport JSON

```bash
python scripts/test_localhost_routes.py --report-file reports/api-smoke.json
```

### Tester aussi les routes mutables revertibles

```bash
python scripts/test_localhost_routes.py \
  --include-mutations \
  --report-file reports/api-smoke.json
```

Cela couvre notamment :

- renommage / changement d'etat / couleur d'une source avec revert ;
- patch d'un label CTI et revert ;
- patch SMTP sur `smtp_from_name` ;
- creation / patch / suppression d'une config de collecteur de test ;
- patch d'une retention policy avec revert.

### Tester aussi les routes externes

```bash
python scripts/test_localhost_routes.py \
  --include-mutations \
  --include-external \
  --report-file reports/api-smoke.json
```

Cela ajoute :

- enrichissements CTI ;
- activation d'une config de collecteur existante si une config compatible est
  detectee ;
- activation SMTP si tu combines aussi avec `--include-destructive`.

### Tester aussi les routes destructives

```bash
python scripts/test_localhost_routes.py \
  --include-mutations \
  --include-external \
  --include-destructive \
  --report-file reports/api-smoke.json
```

Attention :

- ce mode peut desactiver SMTP ;
- ce mode peut supprimer le mot de passe SMTP ;
- il est reserve a un environnement de dev ou de recette.

## 3. Plage de dates pour les routes stats/attacks

Le script utilise par defaut une plage glissante sur les 7 derniers jours.

Tu peux la forcer :

```bash
python scripts/test_localhost_routes.py \
  --from 2026-06-01T00:00:00Z \
  --to 2026-06-07T23:59:59Z
```

## 4. IP de test CTI

Par defaut :

```text
8.8.8.8
```

Surcharge possible :

```bash
python scripts/test_localhost_routes.py --cti-test-ip 1.1.1.1
```

## 5. Interpretation du rapport

- `PASS` : la route a repondu avec le statut attendu et un payload coherent ;
- `FAIL` : la route a renvoye un statut inattendu, une erreur reseau ou un
  payload incoherent ;
- `SKIP` : la route n'a pas ete executee, souvent parce qu'elle depend d'un flag
  ou d'une ressource non decouverte.

Bonne pratique :

- commencer par le mode minimal ;
- passer ensuite au mode `--include-mutations` ;
- n'activer `--include-external` et `--include-destructive` que dans un
  environnement maitrise.
