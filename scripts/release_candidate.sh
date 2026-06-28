#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CONFIG_PATH="${AMBY_RC_CONFIG:-config.production.yaml}"
BUNDLE_DIR="${AMBY_RC_BUNDLE_DIR:-evidence/release-candidate/rc-${STAMP}}"
DB_PATH="${AMBY_RC_DB:-${BUNDLE_DIR}/release-candidate.db}"
IMAGE_TAG="${AMBY_RC_IMAGE_TAG:-amby:rc}"
RUN_TESTS="${RUN_TESTS:-1}"
RUN_DOCKER="${RUN_DOCKER:-auto}"
DOCKER_PORT="${AMBY_RC_DOCKER_PORT:-18080}"

export AMBY_DASHBOARD_TOKEN="${AMBY_DASHBOARD_TOKEN:-rc-dashboard-token}"
export AMBY_API_TOKEN="${AMBY_API_TOKEN:-rc-api-token}"
export AMBY_POLICY_SIGNING_KEY="${AMBY_POLICY_SIGNING_KEY:-rc-policy-signing-key}"

mkdir -p "$BUNDLE_DIR"

if [[ "$RUN_TESTS" == "1" ]]; then
  echo "Running tests for release candidate"
  uv run --extra dev python -m pytest >"${BUNDLE_DIR}/test-output.txt"
else
  echo "RUN_TESTS=0; skipping test execution" >"${BUNDLE_DIR}/test-output.txt"
fi

echo "Running fixture predeploy for release candidate"
uv run python -m app.predeploy run \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --suite default \
  --out "${BUNDLE_DIR}/predeploy" \
  --use-fixtures >"${BUNDLE_DIR}/predeploy-result.json"

echo "Creating and activating signed policy bundle"
uv run python -m app.control_plane bundle \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --activate >"${BUNDLE_DIR}/control-policy-bundle.json"

echo "Recording metadata-only heartbeat and drift status"
uv run python -m app.control_plane heartbeat \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" >"${BUNDLE_DIR}/control-heartbeat.json"
uv run python -m app.control_plane drift \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" >"${BUNDLE_DIR}/control-drift.json"

echo "Generating release candidate evidence package"
PACKAGE_JSON="$(uv run python -m app.evidence generate \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --out "${BUNDLE_DIR}/evidence" \
  --name "rc-evidence-${STAMP}")"
PACKAGE_DIR="$(uv run python -c 'import json,sys; print(json.load(sys.stdin)["package_dir"])' <<<"$PACKAGE_JSON")"
printf '%s\n' "$PACKAGE_JSON" >"${BUNDLE_DIR}/evidence-result.json"

echo "Verifying release candidate evidence package"
uv run python -m app.evidence verify "$PACKAGE_DIR" >"${BUNDLE_DIR}/evidence-verify.json"

echo "Writing production diagnostics"
uv run python - "$CONFIG_PATH" "${BUNDLE_DIR}/diagnostics.json" <<'PY'
import json
import sys

from app.config import load_config
from app.diagnostics import build_diagnostics

config = load_config(sys.argv[1])
diagnostics = build_diagnostics(config)
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n")
assert diagnostics["status"] == "ok", diagnostics
assert diagnostics["deployment"]["production_ready"] is True, diagnostics["production_checks"]
PY

cp "$CONFIG_PATH" "${BUNDLE_DIR}/config_snapshot.yaml"

IMAGE_ID=""
DOCKER_SMOKE_PATH="${BUNDLE_DIR}/docker-smoke.json"
if [[ "$RUN_DOCKER" == "auto" ]]; then
  if docker ps >/dev/null 2>&1; then
    RUN_DOCKER="1"
  else
    RUN_DOCKER="0"
  fi
fi

if [[ "$RUN_DOCKER" == "1" ]]; then
  echo "Building Docker image ${IMAGE_TAG}"
  GIT_SHA="$(git rev-parse HEAD 2>/dev/null || true)"
  BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker build \
    --build-arg "BUILD_DATE=${BUILD_DATE}" \
    --build-arg "VCS_REF=${GIT_SHA:-unknown}" \
    --build-arg "VERSION=0.1.0rc1" \
    -t "$IMAGE_TAG" .
  IMAGE_ID="$(docker image inspect "$IMAGE_TAG" --format '{{.Id}}')"

  echo "Running Docker production smoke"
  CONTAINER_ID="$(docker run -d \
    -p "127.0.0.1:${DOCKER_PORT}:8080" \
    -e AMBY_CONFIG=config.production.yaml \
    -e AMBY_DASHBOARD_TOKEN="$AMBY_DASHBOARD_TOKEN" \
    -e AMBY_API_TOKEN="$AMBY_API_TOKEN" \
    -e AMBY_POLICY_SIGNING_KEY="$AMBY_POLICY_SIGNING_KEY" \
    "$IMAGE_TAG")"
  trap 'docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true' EXIT

  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -s "http://127.0.0.1:${DOCKER_PORT}/healthz" >"${BUNDLE_DIR}/docker-healthz.json"; then
      break
    fi
    sleep 1
  done
  curl -s \
    -H "x-amby-api-key: ${AMBY_API_TOKEN}" \
    "http://127.0.0.1:${DOCKER_PORT}/diagnostics" >"${BUNDLE_DIR}/docker-diagnostics.json"
  uv run python -m app.release docker-smoke \
    --healthz "${BUNDLE_DIR}/docker-healthz.json" \
    --diagnostics "${BUNDLE_DIR}/docker-diagnostics.json" \
    --out "$DOCKER_SMOKE_PATH" \
    --image-tag "$IMAGE_TAG" \
    --image-id "$IMAGE_ID" \
    --container-id "$CONTAINER_ID" \
    --secret "$AMBY_DASHBOARD_TOKEN" \
    --secret "$AMBY_API_TOKEN" \
    --secret "$AMBY_POLICY_SIGNING_KEY" >"${BUNDLE_DIR}/docker-smoke-result.json"
else
  echo "RUN_DOCKER=${RUN_DOCKER}; skipping Docker smoke"
  uv run python - "$DOCKER_SMOKE_PATH" <<'PY'
import json
import sys

payload = {
    "schema_version": "amby.docker_smoke.v1",
    "decision": "skip",
    "status": "skipped",
    "reason": "RUN_DOCKER=0 or Docker unavailable.",
    "raw_secret_values_present": False,
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
fi

echo "Writing release candidate manifest, SBOM, and security metadata"
uv run python -m app.release candidate \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --out "$BUNDLE_DIR" \
  --evidence-package "$PACKAGE_DIR" \
  --image-tag "$IMAGE_TAG" \
  --image-id "$IMAGE_ID" \
  --docker-smoke "$DOCKER_SMOKE_PATH" >"${BUNDLE_DIR}/release-result.json"

echo "Release candidate bundle created: ${BUNDLE_DIR}"
