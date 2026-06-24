.PHONY: api scheduler common-ip migrate lint active_lint_on_commit

# Lance l'application API
api:
	uv run --package cyber-dashboard-api uvicorn cyber_dashboard_api.main:app --reload --host 0.0.0.0 --port 8000

# Lance l'application scheduler
scheduler:
	uv run --package cyber-dashboard-scheduler cyber-scheduler

# Lance l'application common-ip
common-ip:
	uv run --package cyber-dashboard-common-ip cyber-common-ip

# Lance le script de migration de la base de données
migrate:
	uv run scripts/migrate.py

# Lance les linters sur tous les fichiers du projet
lint:
	uv run pre-commit run --all-files

# Active les linters pour qu'ils s'exécutent automatiquement avant chaque commit
active_lint_on_commit:
	uv run pre-commit install

# Lance les tests unitaires
# Lance une BDD postgreSQL de test dans un conteneur Docker
