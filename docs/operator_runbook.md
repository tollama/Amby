# Amby Operator Runbook

This runbook covers the self-hosted pilot release candidate.

## Production Environment

Use `config.production.yaml` and set:

```bash
export AMBY_CONFIG=config.production.yaml
export AMBY_DASHBOARD_TOKEN="change-me"
export AMBY_API_TOKEN="change-me"
export AMBY_POLICY_SIGNING_KEY="change-me"
```

Start locally:

```bash
uv run uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Run Docker:

```bash
docker build -t amby:rc .
docker run --rm -p 8080:8080 \
  -e AMBY_CONFIG=config.production.yaml \
  -e AMBY_DASHBOARD_TOKEN="$AMBY_DASHBOARD_TOKEN" \
  -e AMBY_API_TOKEN="$AMBY_API_TOKEN" \
  -e AMBY_POLICY_SIGNING_KEY="$AMBY_POLICY_SIGNING_KEY" \
  amby:rc
```

## Release Candidate

```bash
RUN_DOCKER=0 bash scripts/release_candidate.sh
RUN_DOCKER=1 bash scripts/release_candidate.sh
```

Review `release_manifest.json`, `release_security.json`, `docker-smoke.json`, `control-drift.json`, and `evidence-verify.json`.

## Backup And Restore

- Back up the SQLite audit DB configured by `audit.store`.
- Back up the evidence output directory and local `ledger.jsonl`.
- Restore by placing the DB and evidence directory back at the configured paths before running verification.

Verify restored evidence:

```bash
python -m app.evidence verify evidence/<package>
```

## Signing Key Rotation

Phase 2.6 uses HMAC signing through `AMBY_POLICY_SIGNING_KEY`. To rotate:

1. Set the new `AMBY_POLICY_SIGNING_KEY`.
2. Create and activate a new policy bundle.
3. Restart or redeploy the data plane with the same config.
4. Confirm `/control/drift` reports `clean`.

Historical bundles signed with the old key remain evidence records; they are not re-signed.

## Drift Remediation

If `/control/drift` reports `drift`:

1. Compare `expected_policy_hash` and `running_policy_hash`.
2. Confirm whether a config change was intended.
3. If intended, create and activate a new signed bundle.
4. If unintended, redeploy the reviewed config snapshot.
5. Generate a fresh evidence package and confirm the Control Plane Governance section shows clean state.

## Evidence Review

Minimum files for pilot review:

- `report.md`
- `manifest.json`
- `hashes.sha256`
- `release_manifest.json`
- `release_sbom.json`
- `release_security.json`
- `control_plane.json`
- `control_plane_chain.jsonl`
- `predeploy_chain.jsonl`
- `aibom.json`
- `evidence-verify.json`

