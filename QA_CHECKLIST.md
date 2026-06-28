# Amby QA Gate Checklist

This checklist is the official QA path for proving that the Amby MVP, pilot build, or release candidate is working as intended. Run the gates in order unless a reviewer explicitly accepts a narrower evidence bundle.

## Gate Sequence

| Order | Gate | Command | When to run | Success criteria | Artifacts |
| --- | --- | --- | --- | --- | --- |
| 1 | Unit and integration tests | `uv run --extra dev python -m pytest` | During development and before every handoff | All tests pass. Known warnings must be reviewed, not ignored. | pytest output |
| 2 | Predeploy security smoke | `bash scripts/predeploy_smoke.sh` | Before staging or release packaging | Predeploy run decision is `pass`, every fixture finding is `pass`, and evidence verification succeeds. | `data/predeploy-smoke-*.db`, `evidence/predeploy-smoke`, generated evidence package |
| 3 | Pilot smoke against a running gateway | `bash scripts/pilot_smoke.sh` | Before pilot demo or reviewer walkthrough | `/healthz` is reachable; demo guardrail, tool-call, and context events are generated; runtime and Mythos stats respond; evidence generate/verify passes. | `evidence/pilot-smoke/<package>` |
| 4A | Pilot release gate | `bash scripts/release_gate.sh` | Before pilot reviewer bundle | Tests, fixture predeploy, signed policy bundle, heartbeat, drift check, evidence verify, production diagnostics, and report checks pass. | `evidence/release-gate/release-<timestamp>` plus control-plane JSON files |
| 4B | Release candidate bundle | `RUN_TESTS=1 RUN_DOCKER=1 bash scripts/release_candidate.sh` | Before release-candidate sign-off | Predeploy decision is `pass`, diagnostics `status=ok`, `production_ready=true`, drift is clean, evidence verify is valid, and Docker smoke passes. | `evidence/release-candidate/rc-<timestamp>` |

## Practical Short Path

```bash
uv run --extra dev python -m pytest
bash scripts/predeploy_smoke.sh
bash scripts/pilot_smoke.sh
bash scripts/release_gate.sh
```

Use the release-candidate bundle when the reviewer needs a single directory with release manifest, SBOM, security metadata, Docker smoke status, control-plane evidence, and the full evidence package:

```bash
RUN_TESTS=1 RUN_DOCKER=1 bash scripts/release_candidate.sh
```

## Fast Documentation Bundle

For a fast deterministic bundle check in CI or documentation review, use:

```bash
RUN_TESTS=0 RUN_DOCKER=0 bash scripts/release_candidate.sh
```

This mode intentionally skips tests and Docker smoke, so `release_manifest.json` may report `decision: warn`. Do not use this as final release sign-off.

## Gateway Assumptions

`scripts/pilot_smoke.sh` targets an already running gateway at `BASE_URL`, defaulting to `http://127.0.0.1:8080`. It is intended for a local/dev gateway with management auth disabled. If the gateway is running with production API auth enabled, use the release gate or release-candidate path instead.

## CI Baseline

The current GitHub Actions workflow is a pilot CI baseline. It runs:

- `uv run --extra dev python -m pytest`
- `bash scripts/predeploy_smoke.sh`
- `RUN_TESTS=0 RUN_DOCKER=0 bash scripts/release_candidate.sh`

Public release CI remains a later hardening step and should add `npm ci`, online vulnerability audits, required Docker smoke, release artifact upload, and release/tag publishing.

## What This Proves

Passing all four gates proves that the current repo can execute the Amby runtime checks, predeploy governance checks, evidence generation and verification, production diagnostics, local signed policy bundle flow, heartbeat, drift detection, and release-candidate packaging. It does not replace post-RC controls such as SSO/RBAC, WORM/notarization, image signing, or enforced online vulnerability scanning.
