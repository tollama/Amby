#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CONFIG_PATH="${AMBY_RELEASE_CONFIG:-config.production.yaml}"
DB_PATH="${AMBY_RELEASE_DB:-./data/release-gate-${STAMP}.db}"
OUT_ROOT="${AMBY_RELEASE_OUT:-evidence/release-gate}"

export AMBY_DASHBOARD_TOKEN="${AMBY_DASHBOARD_TOKEN:-release-dashboard-token}"
export AMBY_API_TOKEN="${AMBY_API_TOKEN:-release-api-token}"
export AMBY_RUNTIME_KEY="${AMBY_RUNTIME_KEY:-release-runtime-token}"
export AMBY_POLICY_SIGNING_KEY="${AMBY_POLICY_SIGNING_KEY:-release-policy-signing-key}"

mkdir -p "$OUT_ROOT"

echo "Running unit and integration tests"
uv run --extra dev python -m pytest

echo "Running fixture predeploy gate"
uv run python -m app.predeploy run \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --suite default \
  --out "$OUT_ROOT/predeploy" \
  --use-fixtures

echo "Creating and activating signed policy bundle"
uv run python -m app.control_plane bundle \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --activate >"$OUT_ROOT/control-policy-bundle.json"

echo "Recording metadata-only fleet heartbeat"
uv run python -m app.control_plane heartbeat \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" >"$OUT_ROOT/control-heartbeat.json"

echo "Checking policy drift"
uv run python -m app.control_plane drift \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" >"$OUT_ROOT/control-drift.json"

echo "Generating release evidence package"
PACKAGE_JSON="$(uv run python -m app.evidence generate \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --out "$OUT_ROOT" \
  --name "release-${STAMP}")"
PACKAGE_DIR="$(uv run python -c 'import json,sys; print(json.load(sys.stdin)["package_dir"])' <<<"$PACKAGE_JSON")"

echo "Verifying release evidence package: ${PACKAGE_DIR}"
uv run python -m app.evidence verify "$PACKAGE_DIR"

echo "Checking production diagnostics"
uv run python - "$CONFIG_PATH" <<'PY'
import json
import sys

from app.config import load_config
from app.diagnostics import build_diagnostics

config = load_config(sys.argv[1])
diagnostics = build_diagnostics(config)
print(json.dumps({
    "status": diagnostics["status"],
    "deployment": diagnostics["deployment"],
    "policy_hash": diagnostics["policy_hash"],
    "config_hash": diagnostics["config_hash"],
}, indent=2, sort_keys=True))
assert diagnostics["status"] == "ok", diagnostics
assert diagnostics["deployment"]["production_ready"] is True, diagnostics["production_checks"]
PY

echo "Checking release evidence report"
uv run python - "$PACKAGE_DIR" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
report = (root / "report.md").read_text(encoding="utf-8")
assert manifest["source"]["policy_hash"] in report
assert manifest["source"]["config_hash"] in report
assert manifest["ledger"]["enabled"] is True
assert "Pre-deploy Governance" in report
assert "Control Plane Governance" in report
assert "Evidence ledger" in report
assert "control_plane.json" in manifest["files"]
PY

echo "Release gate passed: ${PACKAGE_DIR}"
