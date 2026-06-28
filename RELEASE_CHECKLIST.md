# Amby Release Candidate Checklist

This checklist is for a pilot release candidate. It is not a regulated-production WORM/notarized release process.

## Required Environment

Set these before running production or release-candidate commands:

```bash
export AMBY_DASHBOARD_TOKEN="change-me"
export AMBY_API_TOKEN="change-me"
export AMBY_POLICY_SIGNING_KEY="change-me"
```

Optional release-candidate inputs:

```bash
export AMBY_RC_CONFIG=config.production.yaml
export AMBY_RC_IMAGE_TAG=amby:rc
export RUN_TESTS=1
export RUN_DOCKER=0
```

Use `RUN_DOCKER=1` when Docker is available and a container smoke test should be part of the candidate bundle.

## Commands

```bash
uv run --extra dev python -m pytest
bash scripts/release_gate.sh
RUN_TESTS=0 bash scripts/pilot_bundle.sh
RUN_DOCKER=0 bash scripts/release_candidate.sh
```

Optional Docker smoke:

```bash
RUN_DOCKER=1 bash scripts/release_candidate.sh
```

## Expected Release Candidate Artifacts

`scripts/release_candidate.sh` writes `evidence/release-candidate/rc-<timestamp>/` with:

- `release_manifest.json`
- `release_sbom.json`
- `release_security.json`
- `docker-smoke.json`
- `control-policy-bundle.json`
- `control-heartbeat.json`
- `control-drift.json`
- `diagnostics.json`
- `predeploy-result.json`
- `evidence-result.json`
- `evidence-verify.json`
- `config_snapshot.yaml`
- `evidence/`
- `README.md`

## Sign-off Criteria

- Tests pass or are explicitly skipped only for a documented reviewer bundle.
- Predeploy decision is `pass`.
- `/diagnostics` status is `ok` and `deployment.production_ready` is `true`.
- `control-drift.json` status is `clean`.
- Evidence verification result is `valid=true`.
- Docker smoke is `pass` when `RUN_DOCKER=1`; `skip` is acceptable only when Docker is unavailable or intentionally disabled.
- Release artifacts do not contain raw dashboard/API tokens, policy signing keys, prompts, responses, or raw scanner output.

