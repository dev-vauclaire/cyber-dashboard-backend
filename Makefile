.PHONY: api scheduler common-ip migrate db-seed-dev run_pre_commit activate_pre_commit update_pre_commit

########################
### Application commands
########################
# Lance l'application API
api:
	uv run --package cyber-dashboard-api uvicorn cyber_dashboard_api.main:app --reload --host 127.0.0.1 --port 8000

# Lance l'application scheduler
scheduler:
	uv run --package cyber-dashboard-scheduler cyber-scheduler

# Lance l'application common-ip
common-ip:
	uv run --package cyber-dashboard-common-ip cyber-common-ip

# Lance le script de migration de la base de données
migrate:
	uv run python scripts/db/migrate.py

# Insere ou met a jour un jeu de donnees complet dans la base de donnees
db-seed-dev:
	uv run python scripts/db/seed_dev.py

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
