# Amby OSS Release Checklist

This checklist prepares the GitHub-only Apache-2.0 public release candidate `v0.1.0-rc1`.

## 1. Repository Hygiene

- Confirm `LICENSE` is Apache-2.0.
- Confirm `NOTICE` includes Amby copyright, third-party dependency notice policy, and CSA Mythos reference attribution.
- Confirm `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `.github/CODEOWNERS` exist.
- Confirm `pyproject.toml`, `package.json`, and `package-lock.json` include license, repository, homepage, issues, and release version metadata.
- Confirm generated artifacts, local DB files, `.amby-predeploy`, `node_modules`, and evidence directories remain ignored.

## 2. Public Positioning

- README states that this is a pilot RC, not regulated production.
- README links to legal, security, contribution, QA, standards coverage, standards checklist, release checklist, and release notes documents.
- README and `docs/security_model.md` warn that `/v1/*` model proxy endpoints are not protected by production management API auth in this RC.
- Public docs state that PyPI publishing, Docker registry publishing, image signing, SSO/RBAC, WORM/notarization, and enforced online vulnerability scanning are post-RC.
- `SECURITY_STANDARDS.md` and `SECURITY_STANDARDS_CHECKLIST.md` distinguish implemented, partial, planned, candidate, reference-only, and out-of-scope standards before the release is tagged.

## 3. Version And Tagging

- Python/app version: `0.1.0rc1`.
- GitHub tag: `v0.1.0-rc1`.
- Changelog section: `0.1.0-rc1 - 2026-06-28`.
- Release notes: `docs/release_notes_v0.1.0-rc1.md`.

## 4. QA Gates

Run the canonical QA sequence:

```bash
uv run --extra dev python -m pytest
bash scripts/predeploy_smoke.sh
bash scripts/pilot_smoke.sh
bash scripts/release_gate.sh
RUN_TESTS=1 RUN_DOCKER=1 bash scripts/release_candidate.sh
```

`bash scripts/pilot_smoke.sh` requires a running local/dev gateway. `RUN_TESTS=0 RUN_DOCKER=0 bash scripts/release_candidate.sh` is acceptable only for fast CI/documentation checks and is not final sign-off.

## 5. Supply-Chain Checks

Run and record:

```bash
npm audit --audit-level=high
uv export --no-dev --format requirements-txt --no-hashes --output-file /tmp/amby-runtime-requirements.txt
uv run --with pip-audit pip-audit -r /tmp/amby-runtime-requirements.txt
```

Attach or summarize the results in the GitHub release notes. Known moderate Node findings may be documented when there are no high/critical findings.

## 6. GitHub Release Artifacts

Attach the final RC bundle's:

- `release_manifest.json`
- `release_sbom.json`
- `release_security.json`
- `docker-smoke.json`
- `control-drift.json`
- `evidence-verify.json`
- bundle `README.md`

Do not publish PyPI packages or Docker registry images for this RC.
