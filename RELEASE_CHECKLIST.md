# Amby Release Candidate Checklist

This checklist is for a pilot release candidate. It is not a regulated-production WORM/notarized release process.

## OSS Public Release Baseline

The first public OSS release is GitHub-only under Apache-2.0. Before tagging `v0.1.0-rc1`, confirm these files are present and linked from the README:

- `LICENSE`
- `NOTICE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `.github/CODEOWNERS`
- `QA_CHECKLIST.md`
- `OSS_RELEASE_CHECKLIST.md`
- `docs/release_notes_v0.1.0-rc1.md`

Do not publish to PyPI or a Docker registry for this RC. Attach the release-candidate bundle artifacts to the GitHub release instead.

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

For a GitHub-only OSS release, attach the core release evidence files from the final RC bundle: `release_manifest.json`, `release_sbom.json`, `release_security.json`, `docker-smoke.json`, `control-drift.json`, `evidence-verify.json`, and `README.md`.

## QA Gate Sequence

Run the gates in [QA_CHECKLIST.md](QA_CHECKLIST.md) before sign-off:

```bash
uv run --extra dev python -m pytest
bash scripts/predeploy_smoke.sh
bash scripts/pilot_smoke.sh
bash scripts/release_gate.sh
RUN_TESTS=1 RUN_DOCKER=1 bash scripts/release_candidate.sh
```

`scripts/pilot_smoke.sh` requires a running local/dev gateway and assumes management auth is off. For a quick deterministic bundle check, `RUN_TESTS=0 RUN_DOCKER=0 bash scripts/release_candidate.sh` is acceptable, but the resulting release manifest may be `warn` and is not final release sign-off.

## Sign-off Criteria

- Tests pass or are explicitly skipped only for a documented reviewer bundle.
- Predeploy decision is `pass`.
- `/diagnostics` status is `ok` and `deployment.production_ready` is `true`.
- `control-drift.json` status is `clean`.
- Evidence verification result is `valid=true`.
- Docker smoke is `pass` when `RUN_DOCKER=1`; `skip` is acceptable only when Docker is unavailable or intentionally disabled.
- Release artifacts do not contain raw dashboard/API tokens, policy signing keys, prompts, responses, or raw scanner output.
