#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CONFIG_PATH="${AMBY_PILOT_CONFIG:-config.production.yaml}"
BUNDLE_DIR="${AMBY_PILOT_BUNDLE_DIR:-evidence/pilot-bundle/pilot-${STAMP}}"
DB_PATH="${AMBY_PILOT_DB:-${BUNDLE_DIR}/pilot.db}"

export AMBY_DASHBOARD_TOKEN="${AMBY_DASHBOARD_TOKEN:-pilot-dashboard-token}"
export AMBY_API_TOKEN="${AMBY_API_TOKEN:-pilot-api-token}"
export AMBY_RUNTIME_KEY="${AMBY_RUNTIME_KEY:-pilot-runtime-token}"
export AMBY_POLICY_SIGNING_KEY="${AMBY_POLICY_SIGNING_KEY:-pilot-policy-signing-key}"

mkdir -p "$BUNDLE_DIR"

if [[ "${RUN_TESTS:-1}" == "1" ]]; then
  echo "Running tests for pilot bundle"
  uv run --extra dev python -m pytest >"${BUNDLE_DIR}/test-output.txt"
else
  echo "RUN_TESTS=0; skipping test execution" >"${BUNDLE_DIR}/test-output.txt"
fi

echo "Running fixture predeploy for pilot bundle"
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

echo "Recording control-plane heartbeat and drift status"
uv run python -m app.control_plane heartbeat \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" >"${BUNDLE_DIR}/control-heartbeat.json"
uv run python -m app.control_plane drift \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" >"${BUNDLE_DIR}/control-drift.json"

echo "Generating evidence package"
PACKAGE_JSON="$(uv run python -m app.evidence generate \
  --config "$CONFIG_PATH" \
  --db "$DB_PATH" \
  --out "${BUNDLE_DIR}/evidence" \
  --name "pilot-evidence-${STAMP}")"
PACKAGE_DIR="$(uv run python -c 'import json,sys; print(json.load(sys.stdin)["package_dir"])' <<<"$PACKAGE_JSON")"
printf '%s\n' "$PACKAGE_JSON" >"${BUNDLE_DIR}/evidence-result.json"

echo "Verifying evidence package"
uv run python -m app.evidence verify "$PACKAGE_DIR" >"${BUNDLE_DIR}/evidence-verify.json"

echo "Writing diagnostics and SIEM JSONL exports"
uv run python - "$CONFIG_PATH" "$DB_PATH" "$BUNDLE_DIR" "$PACKAGE_DIR" <<'PY'
import json
import sys
from pathlib import Path

from app.audit.store import AuditStore
from app.config import load_config
from app.control_plane.store import ControlPlaneStore
from app.diagnostics import build_diagnostics

config_path = sys.argv[1]
db_path = sys.argv[2]
bundle_dir = Path(sys.argv[3])
package_dir = Path(sys.argv[4])

config = load_config(config_path)
diagnostics = build_diagnostics(config)
(bundle_dir / "diagnostics.json").write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8")

store = AuditStore(db_path)
control_store = ControlPlaneStore(db_path)
control_store.initialize()
streams = [
    ("guardrail", store.export_events()),
    ("tool_call", store.export_tool_call_events()),
    ("context", store.export_context_events()),
    ("predeploy_run", store.export_predeploy_runs()),
    ("predeploy_finding", store.export_predeploy_findings()),
    ("policy_bundle", control_store.export_policy_bundles()),
    ("fleet_heartbeat", control_store.export_fleet_heartbeats()),
    ("policy_drift", control_store.export_drift_events()),
]
with (bundle_dir / "audit-all.jsonl").open("w", encoding="utf-8") as handle:
    for event_type, rows in streams:
        for row in rows:
            handle.write(json.dumps({"schema_version": "amby.audit_jsonl.v1", "event_type": event_type, **row}, sort_keys=True, separators=(",", ":")) + "\n")

manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))
ledger_path = Path(manifest["ledger"]["path"])
ledger_entry = None
if ledger_path.exists():
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("manifest_hash") == manifest["manifest_hash"]:
            ledger_entry = row
(bundle_dir / "ledger-entry.json").write_text(json.dumps(ledger_entry or {}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cp "$CONFIG_PATH" "${BUNDLE_DIR}/config_snapshot.yaml"

cat >"${BUNDLE_DIR}/README.md" <<EOF
# Amby Pilot Review Bundle

- Generated at: ${STAMP}
- Config: ${CONFIG_PATH}
- Audit DB: ${DB_PATH}
- Evidence package: ${PACKAGE_DIR}

## Review Files

- \`diagnostics.json\`: production-readiness checks, config hash, policy hash, and sanitized token presence.
- \`test-output.txt\`: unit and integration test output.
- \`predeploy-result.json\`: fixture red-team/predeploy gate result.
- \`control-policy-bundle.json\`: signed expected policy bundle activated for this pilot review.
- \`control-heartbeat.json\`: metadata-only node heartbeat with counts and policy hashes.
- \`control-drift.json\`: active bundle versus running config/policy hash check.
- \`evidence-result.json\`: generated evidence package location and manifest hash.
- \`evidence-verify.json\`: manifest, file hash, chain, and ledger verification result.
- \`audit-all.jsonl\`: SIEM-friendly merged audit stream.
- \`ledger-entry.json\`: local ledger entry for the generated evidence package.
- \`config_snapshot.yaml\`: reviewed production profile.
- \`evidence/\`: full evidence package directory.

This bundle is pilot-review evidence, not formal WORM/notarized production evidence.
EOF

echo "Pilot bundle created: ${BUNDLE_DIR}"
