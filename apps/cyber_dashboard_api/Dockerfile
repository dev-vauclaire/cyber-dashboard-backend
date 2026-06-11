FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/apps/cyber_dashboard_api:/app

WORKDIR /app/apps/cyber_dashboard_api

RUN groupadd --system appuser \
    && useradd --system --gid appuser --create-home --home-dir /home/appuser appuser

COPY apps/cyber_dashboard_api/requirements.txt /tmp/requirements.txt

RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt

COPY --chown=appuser:appuser packages /app/packages
COPY --chown=appuser:appuser apps/cyber_dashboard_api /app/apps/cyber_dashboard_api

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "cyber_dashboard_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
