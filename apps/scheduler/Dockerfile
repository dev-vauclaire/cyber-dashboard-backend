FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system appuser \
    && useradd --system --gid appuser --create-home --home-dir /home/appuser appuser

COPY apps/scheduler/requirements.txt ./requirements.txt

RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY apps/scheduler/cyber_dashboard_scheduler ./cyber_dashboard_scheduler
COPY packages ./packages

USER appuser

CMD ["python", "-m", "cyber_dashboard_scheduler.main"]
