# Amby v0.1.0-rc1 Release Notes

This is the first GitHub-only Apache-2.0 public release candidate for Amby. It is intended for local evaluation, pilot review, and evidence workflow validation. It is not a regulated-production release.

## Highlights

- Runtime guardrails for prompt injection, PII, secrets, system prompt leakage, and improper output handling.
- Agent tool-call firewall with inventory, egress policy, high-risk approval records, and circuit breaker evidence.
- LangGraph/CrewAI/LlamaIndex-style memory and RAG hook contracts.
- Local MCP/plugin/skill discovery and recommended default catalog.
- Predeploy governance with Garak/PyRIT/Promptfoo adapters, fixture smoke mode, AIBOM, and CI evidence.
- Local control-plane foundation with HMAC signed policy bundles, metadata-only heartbeat, and drift detection.
- Release-candidate bundle with manifest, SBOM, security metadata, Docker smoke output, and evidence verification.

## Required QA Evidence

Final sign-off should use the root `QA_CHECKLIST.md` sequence:

```bash
uv run --extra dev python -m pytest
bash scripts/predeploy_smoke.sh
bash scripts/pilot_smoke.sh
bash scripts/release_gate.sh
RUN_TESTS=1 RUN_DOCKER=1 bash scripts/release_candidate.sh
```

The GitHub release should attach the final RC bundle's `release_manifest.json`, `release_sbom.json`, `release_security.json`, `docker-smoke.json`, `control-drift.json`, `evidence-verify.json`, and bundle `README.md`.

## Supply-Chain Notes

- Runtime Python dependency audit on 2026-06-28: no known vulnerabilities from `pip-audit -r /tmp/amby-runtime-requirements.txt`; local package `amby` is not on PyPI and is skipped by the auditor.
- Node audit on 2026-06-28: `npm audit --audit-level=high` exits 0 with no high or critical findings; 9 moderate Promptfoo/OpenTelemetry dependency-chain advisories remain documented.
- Known pilot limitation: online vulnerability scanning is documented but not enforced as a blocking release gate in this RC.
- Docker registry publishing and image signing are out of scope for this GitHub-only release.

## Known Limitations

- `/v1/*` model proxy endpoints are not protected by production management API auth; bind to localhost or trusted network controls.
- Evidence ledger is local continuity evidence, not WORM storage or external notarization.
- Policy signing uses HMAC-SHA256, not asymmetric signer identity.
- SSO/RBAC, virtual keys, SaaS control plane, remote policy push, full VulnOps, and automated response remain post-RC scope.
