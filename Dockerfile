FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 6060
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:6060/api/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:6060", "--workers", "2", "--timeout", "120", \
     "ai_log_analyzer.web.app:create_app()"]
