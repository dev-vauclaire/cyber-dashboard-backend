# Tests de l'API

## Tests unitaires

La suite principale utilise `unittest`. Depuis la racine du monorepo :

```bash
uv sync --all-packages --locked
uv run --directory apps/cyber_dashboard_api python -m unittest tests.test_all
```

Elle couvre les attaques, alertes, configurations de collecteurs, CTI,
dashboard, sante, retention, SMTP, sources et statistiques. Les tests doivent
prioritairement verifier les services, les routes, les erreurs metier et la
forme des reponses.

## Smoke test HTTP local

Le script `apps/cyber_dashboard_api/scripts/test_localhost_routes.py` appelle
une API reelle sur `localhost`.

Prerequis :

1. demarrer l'API avec `make api` ;
2. rendre PostgreSQL accessible ;
3. fournir des configurations valides pour les routes externes testees.

Commande minimale :

```bash
uv run --package cyber-dashboard-api \
  python apps/cyber_dashboard_api/scripts/test_localhost_routes.py
```

La commande teste les lectures et la sante, affiche `PASS`, `FAIL` ou `SKIP`,
et renvoie un code `1` en cas d'echec.

### Rapport JSON

```bash
uv run --package cyber-dashboard-api \
  python apps/cyber_dashboard_api/scripts/test_localhost_routes.py \
  --report-file apps/cyber_dashboard_api/reports/api-smoke.json
```

### Routes mutables reversibles

```bash
uv run --package cyber-dashboard-api \
  python apps/cyber_dashboard_api/scripts/test_localhost_routes.py \
  --include-mutations \
  --report-file apps/cyber_dashboard_api/reports/api-smoke.json
```

Ce mode couvre notamment les modifications de sources, CTI, SMTP, collecteurs
et politiques de retention, avec retour a l'etat initial.

### Integrations externes

```bash
uv run --package cyber-dashboard-api \
  python apps/cyber_dashboard_api/scripts/test_localhost_routes.py \
  --include-mutations \
  --include-external \
  --report-file apps/cyber_dashboard_api/reports/api-smoke.json
```

Ce mode ajoute les enrichissements CTI et les activations qui dependent de
services externes disponibles.

### Operations destructives

```bash
uv run --package cyber-dashboard-api \
  python apps/cyber_dashboard_api/scripts/test_localhost_routes.py \
  --include-mutations \
  --include-external \
  --include-destructive \
  --report-file apps/cyber_dashboard_api/reports/api-smoke.json
```

Ce dernier mode peut desactiver SMTP ou supprimer son mot de passe. Il est
reserve aux environnements de developpement ou de recette.

## Parametres utiles

La plage de dates par defaut couvre les sept derniers jours. Elle peut etre
forcee :

```bash
uv run --package cyber-dashboard-api \
  python apps/cyber_dashboard_api/scripts/test_localhost_routes.py \
  --from 2026-06-01T00:00:00Z \
  --to 2026-06-07T23:59:59Z
```

L'IP CTI par defaut est `8.8.8.8` et peut etre surchargee avec
`--cti-test-ip 1.1.1.1`.

## Interpretation

- `PASS` : statut et payload conformes ;
- `FAIL` : statut inattendu, erreur reseau ou payload incoherent ;
- `SKIP` : route non executee faute de flag ou de ressource disponible.

Commencer par le mode minimal, puis activer progressivement les mutations et
les dependances externes.
