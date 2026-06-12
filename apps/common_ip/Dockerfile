FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system appuser \
    && useradd --system --gid appuser --create-home --home-dir /home/appuser appuser

COPY apps/common_ip/requirements.txt ./apps/common_ip/requirements.txt

RUN python -m pip install --upgrade pip \
    && pip install -r apps/common_ip/requirements.txt

COPY packages ./packages
COPY apps/common_ip ./apps/common_ip

USER appuser

WORKDIR /app/apps/common_ip

CMD ["python", "-m", "common_ip_correlator.main"]
