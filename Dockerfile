FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AMBY_AUDIT_STORE=/data/audit.db \
    PORT=8080

WORKDIR /app
COPY pyproject.toml README.md ./
COPY app ./app
COPY config.yaml ./config.yaml

RUN pip install --no-cache-dir .
RUN mkdir -p /data

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
