# syntax=docker/dockerfile:1

# -------- build stage --------
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        dnsutils \
        libpq-dev \
        gcc \
        python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt requirements.txt

RUN pip wheel --no-cache-dir --no-deps -w /wheels -r requirements.txt

# -------- runtime stage --------
FROM python:3.11-slim-bookworm

# OCI image metadata (helps scanners / registries identify the image)
LABEL org.opencontainers.image.title="PyGoat" \
      org.opencontainers.image.description="Intentionally vulnerable Django application used for DevSecOps training" \
      org.opencontainers.image.source="https://github.com/Basinkse21/pygoat" \
      org.opencontainers.image.base.name="docker.io/library/python:3.11-slim-bookworm" \
      org.opencontainers.image.licenses="MIT"

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        curl \
        libpq5 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

COPY . /app/

EXPOSE 8000

# The root URL is served by the Django app once migrations have been applied.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://localhost:8000/ || exit 1

# Apply migrations on first start so the image can be used standalone with
# `docker run`. `docker compose` keeps its dedicated migration service and
# overrides this CMD with plain gunicorn.
CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn --bind 0.0.0.0:8000 --workers 4 --worker-class gthread --threads 4 --timeout 600 pygoat.wsgi"]
