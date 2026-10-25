# syntax=docker/dockerfile:1

# Base image. The tag keeps this readable; for reproducible builds pin a digest
# (resolve it with `docker buildx imagetools inspect python:3.12-slim`):
#   docker build --build-arg PYTHON_IMAGE=python:3.12-slim@sha256:<digest> .
ARG PYTHON_IMAGE=python:3.12-slim

# ── build stage: wheel-install the package (non-editable) into /install ──────
FROM ${PYTHON_IMAGE} AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

# ── runtime stage ────────────────────────────────────────────────────────────
FROM ${PYTHON_IMAGE}

# The docker CLI is only needed by the lab "docker exec" / "docker logs" features
# (see the `lab` profile in docker-compose.yml). Off by default: no CLI, no socket.
ARG WITH_DOCKER_CLI=0
RUN if [ "$WITH_DOCKER_CLI" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends docker.io \
        && rm -rf /var/lib/apt/lists/*; \
    fi

COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 --create-home --home-dir /home/netlog netlog \
    && mkdir /data && chown netlog /data

# Fail closed: create_app() refuses to start unless AI_LOG_ANALYZER_API_TOKEN (or the
# RBAC token variables) is set, so this image can never come up as an open admin API.
# Lab docker-exec stays off unless the lab compose service turns it on.
ENV AI_LOG_ANALYZER_REQUIRE_AUTH=1 \
    DOCKER_EXEC_FALLBACK=false \
    PYTHONUNBUFFERED=1

USER netlog
WORKDIR /home/netlog
# State DB / spool / audit log live here when AI_LOG_ANALYZER_STATE_DB=/data/state.db.
VOLUME ["/data"]

EXPOSE 6060
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:6060/api/health', timeout=4)"

# gthread: each live-tail (SSE) stream holds a thread, not a whole worker; keep
# --threads above AI_LOG_ANALYZER_MAX_SSE (default 8) so streams cannot starve the API.
CMD ["gunicorn", "--bind", "0.0.0.0:6060", "--workers", "2", "--worker-class", "gthread", \
     "--threads", "12", "--timeout", "120", "ai_log_analyzer.web.app:create_app()"]
