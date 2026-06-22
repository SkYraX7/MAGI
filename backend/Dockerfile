# MAGI backend image. Build context is the repo root (see docker-compose.yml) so the
# collectors package (shared with the backend) is importable.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# The source packages must be present before `pip install .` builds the wheel
# (setuptools needs the `backend` and `collectors` packages it declares).
COPY pyproject.toml README.md ./
COPY backend/ ./backend/
COPY collectors/ ./collectors/
RUN pip install --upgrade pip && pip install ".[backend]"

COPY keys/ ./keys/

EXPOSE 8000

# Healthcheck hits the readiness probe (Neo4j + Redis).
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz').status==200 else 1)" || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
