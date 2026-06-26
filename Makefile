.PHONY: api scheduler common-ip migrate lint active_lint_on_commit

########################
### Application commands
########################
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

########################
### pre-commit commands
########################

# Lance les hooks sur tous les fichiers du projet
run_pre_commit:
	uv run pre-commit run --all-files

# Active les linters pour qu'ils s'exécutent automatiquement avant chaque commit
activate_pre_commit:
	uv run pre-commit install

update_pre_commit:
	uv run pre-commit autoupdate

# Lance les tests unitaires
# Lance une BDD postgreSQL de test dans un conteneur Docker
