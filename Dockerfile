FROM python:3.11-slim

ARG BUILD_DATE="unknown"
ARG VCS_REF="unknown"
ARG VERSION="0.1.0rc1"

LABEL org.opencontainers.image.title="Amby Gateway" \
      org.opencontainers.image.description="AI agent security and governance data plane" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/tollama/amby"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AMBY_AUDIT_STORE=/data/audit.db \
    PORT=8080

WORKDIR /app
COPY pyproject.toml README.md ./
COPY app ./app
COPY config.yaml ./config.yaml
COPY config.production.yaml ./config.production.yaml

RUN pip install --no-cache-dir . \
    && mkdir -p /data \
    && addgroup --system amby \
    && adduser --system --ingroup amby --home /app amby \
    && chown -R amby:amby /app /data

USER amby

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
