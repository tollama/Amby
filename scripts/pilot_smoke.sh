#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-evidence/pilot-smoke}"
PACKAGE_NAME="${PACKAGE_NAME:-pilot-$(date -u +%Y%m%dT%H%M%SZ)}"

echo "Checking Amby gateway at ${BASE_URL}"
for attempt in 1 2 3 4 5; do
  if curl -s "${BASE_URL}/healthz" >/dev/null; then
    break
  fi
  if [[ "${attempt}" == "5" ]]; then
    echo "Gateway is not reachable: ${BASE_URL}" >&2
    exit 1
  fi
  sleep 1
done

echo "Injecting demo attack"
curl -s -X POST "${BASE_URL}/demo/inject" >/dev/null

echo "Injecting demo tool call"
curl -s -X POST "${BASE_URL}/demo/tool-call" >/dev/null
curl -s "${BASE_URL}/agent/tool-calls/events?limit=1" >/dev/null

echo "Injecting demo framework context"
curl -s -X POST "${BASE_URL}/demo/context" >/dev/null
curl -s "${BASE_URL}/frameworks/context/events?limit=1" >/dev/null
curl -s "${BASE_URL}/frameworks/inventory/discover" >/dev/null

echo "Checking runtime and Mythos stats"
curl -s "${BASE_URL}/stats/runtime" >/dev/null
curl -s "${BASE_URL}/stats/mythos" >/dev/null

echo "Generating evidence package"
PACKAGE_JSON="$(uv run python -m app.evidence generate --out "${EVIDENCE_ROOT}" --name "${PACKAGE_NAME}")"
PACKAGE_DIR="$(uv run python -c 'import json,sys; print(json.load(sys.stdin)["package_dir"])' <<<"${PACKAGE_JSON}")"

echo "Verifying evidence package: ${PACKAGE_DIR}"
uv run python -m app.evidence verify "${PACKAGE_DIR}" >/dev/null

echo "Checking Mythos report section"
uv run python -c 'from pathlib import Path; import sys; text=Path(sys.argv[1], "report.md").read_text(); assert "Mythos-ready Coverage" in text; assert "Implemented Controls" in text' "${PACKAGE_DIR}"
uv run python -c 'from pathlib import Path; import sys; root=Path(sys.argv[1]); assert (root / "tool_call_events.jsonl").exists(); assert (root / "tool_call_chain.jsonl").exists(); assert "Tool-call Decision Counts" in (root / "report.md").read_text()' "${PACKAGE_DIR}"
uv run python -c 'from pathlib import Path; import sys; root=Path(sys.argv[1]); assert (root / "context_events.jsonl").exists(); assert (root / "context_chain.jsonl").exists(); assert (root / "discovered_inventory.json").exists(); assert "Context Hook Decision Counts" in (root / "report.md").read_text()' "${PACKAGE_DIR}"

echo "Pilot smoke passed: ${PACKAGE_DIR}"
