ARG PYTHON_IMAGE=python:3.12-slim
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.21

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS dependencies

# Variables d'environnement pour optimiser le build et l'execution
# UV_COMPILE_BYTECODE=1 : compile les fichiers .py en .pyc pour une execution plus rapide
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Récupère le binaire uv et uvx depuis l'image uv
COPY --from=uv /uv /uvx /bin/

# Récupère les fichiers de dépendances de toutes les applications et packages
COPY pyproject.toml uv.lock README.md ./
COPY apps/cyber_dashboard_api/pyproject.toml apps/cyber_dashboard_api/README.md apps/cyber_dashboard_api/
COPY apps/cyber_dashboard_common_ip/pyproject.toml apps/cyber_dashboard_common_ip/README.md apps/cyber_dashboard_common_ip/
COPY apps/cyber_dashboard_scheduler/pyproject.toml apps/cyber_dashboard_scheduler/README.md apps/cyber_dashboard_scheduler/
COPY packages/cyber_dashboard_common_tools/pyproject.toml packages/cyber_dashboard_common_tools/README.md packages/cyber_dashboard_common_tools/
COPY packages/cyber_dashboard_database/pyproject.toml packages/cyber_dashboard_database/README.md packages/cyber_dashboard_database/

# On créer un environnement virtuel uniquement avec les dépendances pour lancer le script de migration.
# --locked : S'assure que l'on ne change pas le fichier uv.lock, si le fichier uv.lock n'est pas présent ou n'est pas à jour par rapport au fichier pyproject.toml la commande échoue
# --no-dev : N'installe pas les dépendances de développement
# --package <package_name> : Installe uniquement les dépendances de l'application spécifiée, si le package n'existe pas dans le workspace la commande échoue
# --no-install-workspace : N'installe pas les dépendances des autres applications et packages du workspace si elles ne sont pas nécessaires pour l'application spécifiée
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --package cyber-dashboard-api --no-install-workspace

# Intermédiaire pour builder l'image finale de production
FROM dependencies AS production-builder

COPY . .

# On update l'environnement virtuel avec les packages locaux
# --frozen : Prend le fichier uv.lock comme source de vérité, si le fichier uv.lock n'est pas présent la commande échoue
# --no-editable : Fais une copie du code source et de ses packages dans l'environnement virtuel
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package cyber-dashboard-api --no-editable

FROM ${PYTHON_IMAGE} AS production

# Le path python est mis à jour vers notre environnement virtuel
# PYTHONDONTWRITEBYTECODE=1 : empêche la création de fichiers .pyc pour éviter d'avoir des fichiers inutiles dans l'image finale
# PYTHONUNBUFFERED=1 : empêche le buffering de la sortie standard et de l'erreur standard pour que les logs soient affichés en temps réel
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# On crée un utilisateur non root pour exécuter l'application
RUN groupadd --system appuser \
    && useradd --system --gid appuser --create-home --home-dir /home/appuser appuser

# On copie ce qui est utile pour lancer l'API
# .venv : l'environnement virtuel avec toutes les dépendances installées
# apps/cyber_dashboard_api : le code source de l'application
COPY --from=production-builder --chown=appuser:appuser /app/.venv /app/.venv

USER appuser

EXPOSE 8000

# On ajoute un healthcheck pour vérifier que l'API est bien démarrée et répond aux requêtes
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

# Lance l'API avec uvicorn
# --host : écoute sur toutes les interfaces réseau
# --port : écoute sur le port 8000
# --proxy-headers : Indique qu'on se situe derrière un reverse proxy et que l'on souhaite récupérer les headers X-Forwarded-For et X-Forwarded-Proto pour déterminer l'adresse IP du client et le protocole utilisé
CMD ["uvicorn", "cyber_dashboard_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
