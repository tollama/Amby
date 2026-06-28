#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DB_PATH="${AMBY_PREDEPLOY_DB:-./data/predeploy-smoke-${STAMP}.db}"
PREDEPLOY_OUT="${AMBY_PREDEPLOY_OUT:-evidence/predeploy-smoke}"
EVIDENCE_OUT="${AMBY_EVIDENCE_OUT:-evidence}"

uv run python -m app.predeploy run \
  --config config.yaml \
  --db "$DB_PATH" \
  --suite default \
  --out "$PREDEPLOY_OUT" \
  --use-fixtures

PACKAGE_DIR="$(uv run python -m app.evidence generate --config config.yaml --db "$DB_PATH" --out "$EVIDENCE_OUT" | python -c 'import json,sys; print(json.load(sys.stdin)["package_dir"])')"
uv run python -m app.evidence verify "$PACKAGE_DIR"

uv run python - "$DB_PATH" <<'PY'
import sys
from app.audit.store import AuditStore

store = AuditStore(sys.argv[1])
runs = store.list_predeploy_runs(limit=1)
assert runs, "missing predeploy run"
assert runs[0]["decision"] == "pass", runs[0]
findings = store.list_predeploy_findings(run_id=runs[0]["id"], limit=100)
assert findings, "missing predeploy findings"
assert all(finding["decision"] == "pass" for finding in findings), findings
print("predeploy smoke passed")
PY
