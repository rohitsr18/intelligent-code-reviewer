FROM python:3.11-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    PATH="/home/appuser/.local/bin:$PATH"

# Don't run as root in production
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup app/ /app/app/
COPY --chown=appuser:appgroup pyproject.toml /app/

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health/live')" || exit 1

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2"]
