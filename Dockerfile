# ============================================================
# Stage 1: Base — shared runtime dependencies
# ============================================================
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements /app/requirements
RUN python -m pip install --upgrade pip \
    && pip install -r /app/requirements/base.txt

# ============================================================
# Stage 2: Dev — hot-reload, dev extras
# ============================================================
FROM base AS dev

RUN pip install -r /app/requirements/dev.txt
COPY . /app

EXPOSE 8899
CMD ["python", "serve.py"]

# ============================================================
# Stage 3: Test — pytest runner
# ============================================================
FROM base AS test

RUN pip install -r /app/requirements/test.txt
COPY . /app

CMD ["pytest", "-q"]

# ============================================================
# Stage 4: Production — slim, hardened, non-root
# ============================================================
FROM base AS prod

RUN pip install -r /app/requirements/prod.txt
COPY . /app

# Create non-root user "sentinel"
RUN addgroup --system sentinel \
    && adduser --system --ingroup sentinel sentinel \
    && mkdir -p /app/data \
    && chown -R sentinel:sentinel /app

USER sentinel

# Production environment defaults
ENV SENTINEL_DATABASE_URL="postgresql+psycopg2://api_sentinel:api_sentinel@postgres:5432/api_sentinel" \
    SENTINEL_AUTO_CREATE_SCHEMA="false" \
    SENTINEL_AUTH_REQUIRED="true" \
    SENTINEL_AUTH_ALLOW_INSECURE_DEV_TOKENS="false" \
    SENTINEL_AUTH_REQUIRE_VERIFIED_JWT="true" \
    SENTINEL_AUTH_ENFORCE_MAPPED_ROLES="true" \
    SENTINEL_CONNECTOR_SIMULATED_FALLBACK="false" \
    SENTINEL_OLLAMA_BASE_URL="http://ollama:11434"

EXPOSE 8899

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["curl", "-f", "http://127.0.0.1:8899/v1/health"]

CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "-b", "0.0.0.0:8899", "app.main:app"]
