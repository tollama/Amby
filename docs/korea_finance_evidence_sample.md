# Korea Finance Pilot Evidence Sample

This sample maps the current Amby MVP evidence package to a Korean financial-services AI agent pilot. It is not legal advice; it is a pilot review checklist for security, AI governance, and audit teams.

## Scenario

A customer-facing AI agent recommends a card or banking product and may later route the customer to enrollment, payment, or account-servicing workflows.

## Evidence Package

Run:

```bash
scripts/pilot_smoke.sh
scripts/predeploy_smoke.sh
```

Primary artifacts:

- `report.md`: executive evidence summary and Mythos-ready coverage.
- `mythos_ready.json`: implemented / partial / planned Mythos control matrix.
- `audit_events.jsonl`: canonical runtime event export.
- `audit_chain.jsonl`: tamper-evident event hash chain.
- `tool_call_events.jsonl`: high-risk action evaluation, approval, and egress evidence.
- `tool_call_chain.jsonl`: tamper-evident tool-call hash chain.
- `context_events.jsonl`: framework memory/RAG context hook decisions.
- `context_chain.jsonl`: tamper-evident context hook hash chain.
- `predeploy_runs.jsonl`: predeploy governance run evidence.
- `predeploy_findings.jsonl`: normalized red-team, prompt regression, and AIBOM findings.
- `predeploy_chain.jsonl`: tamper-evident predeploy hash chain.
- `aibom.json`: model, prompt, tool, MCP, framework, scanner, and dependency metadata.
- `tool_outputs/`: sanitized scanner output summaries.
- `discovered_inventory.json`: local MCP/plugin/skill discovery snapshot and recommended default catalog.
- `config_snapshot.yaml`: policy snapshot used for the pilot run.
- `hashes.sha256` and `manifest.json`: package integrity proof.
- external `ledger.jsonl`: local continuity ledger for manifest hash and chain heads.

## Financial AI Governance Mapping

| Review concern | Amby MVP evidence | Status |
| --- | --- | --- |
| Transparency | Dashboard and report show each policy decision, scanner, ASI tag, and masked snippet. | Implemented |
| Human oversight / auxiliary use | High-risk tool calls are separated into AI proposal, policy decision, pending approval, and human approval record. | Implemented |
| Security | Prompt injection, PII, secret leakage, tool scope, and egress controls are enforced or evaluated before dispatch. | Implemented |
| Memory/RAG context integrity | Framework hooks evaluate memory writes and retrieved context before they persist or enter the model context. | Implemented |
| Reliability | Mock upstream E2E tests and pilot smoke script prove repeatable behavior without live model dependency. | Implemented |
| Access control | Agent allowed scopes are enforced per tool; managed virtual keys/RBAC remain a later production control. | Partial |
| Data residency | Runtime audit and evidence generation stay local unless the configured upstream model API is called. | Implemented |
| Auditability | JSON/CSV export, hash chain, manifest hash, and config snapshot are generated per package. | Implemented |
| Production readiness | `/diagnostics` and dashboard Production Readiness show whether auth, persistent audit storage, evidence ledger, and predeploy CI gate are enabled. | Implemented |
| Agent attack surface inventory | Configured tools plus local MCP/plugin/skill discovery are exported without storing secret values; recommended MCP/skill catalog is shown separately as non-installed candidates. | Partial |
| Pre-deploy validation | Garak/PyRIT/Promptfoo adapters, fixture smoke mode, CI gate thresholds, normalized findings, and AIBOM are exported before deploy. | Partial |
| Change management | Policy snapshot and predeploy evidence are captured; signed policy bundles and drift detection are Phase 2.5. | Partial |

## Pilot Acceptance Evidence

Minimum evidence to attach to a pilot review:

1. `report.md` with event count, decision counts, ASI counts, and Mythos-ready coverage.
2. `manifest.json` with `manifest_hash`.
3. `audit_chain.jsonl` with a valid chain head.
4. `tool_call_events.jsonl` showing `approval_required`, `approved`, `allow`, or `block` decisions for write actions.
5. `context_events.jsonl` showing `memory_write` and `retrieval_context` decisions without raw memory/context storage.
6. `discovered_inventory.json` showing MCP/plugin/skill inventory metadata, recommended catalog candidates, and no secret values.
7. `predeploy_findings.jsonl`, `predeploy_chain.jsonl`, and `aibom.json` showing what was checked before deploy.
8. `config_snapshot.yaml` showing scanner actions, tool inventory, egress allowlist, approval thresholds, framework hook settings, and predeploy thresholds.
9. `ledger.jsonl` entry showing the package `manifest_hash` and chain heads.
10. `/diagnostics` output with `deployment.mode=production` or `pilot`, production checks, and no token values.
11. Test output showing all E2E, privacy, scanner error, agent firewall, framework adapter, predeploy, and evidence tests passed.

## Known Gaps Before Regulated Production

- Add WORM storage or external notarization on top of the current local ledger.
- Add managed RBAC, virtual keys, SSO, and policy signing.
- Add signed inventory provenance and authoritative owner/RBAC registry.
- Add real-provider red-team suites, LLM PR/code review, dependency vulnerability scan, and patch SLA evidence.
