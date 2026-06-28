# Korea Finance Pilot Evidence Sample

This sample maps the current Amby MVP evidence package to a Korean financial-services AI agent pilot. It is not legal advice; it is a pilot review checklist for security, AI governance, and audit teams.

## Scenario

A customer-facing AI agent recommends a card or banking product and may later route the customer to enrollment, payment, or account-servicing workflows.

## Evidence Package

Run:

```bash
scripts/pilot_smoke.sh
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
- `discovered_inventory.json`: local MCP/plugin/skill discovery snapshot and recommended default catalog.
- `config_snapshot.yaml`: policy snapshot used for the pilot run.
- `hashes.sha256` and `manifest.json`: package integrity proof.

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
| Agent attack surface inventory | Configured tools plus local MCP/plugin/skill discovery are exported without storing secret values; recommended MCP/skill catalog is shown separately as non-installed candidates. | Partial |
| Change management | Policy snapshot is captured; signed policy bundles and drift detection are Phase 2.5. | Planned |

## Pilot Acceptance Evidence

Minimum evidence to attach to a pilot review:

1. `report.md` with event count, decision counts, ASI counts, and Mythos-ready coverage.
2. `manifest.json` with `manifest_hash`.
3. `audit_chain.jsonl` with a valid chain head.
4. `tool_call_events.jsonl` showing `approval_required`, `approved`, `allow`, or `block` decisions for write actions.
5. `context_events.jsonl` showing `memory_write` and `retrieval_context` decisions without raw memory/context storage.
6. `discovered_inventory.json` showing MCP/plugin/skill inventory metadata, recommended catalog candidates, and no secret values.
7. `config_snapshot.yaml` showing scanner actions, tool inventory, egress allowlist, approval thresholds, and framework hook settings.
8. Test output showing all E2E, privacy, scanner error, agent firewall, framework adapter, and evidence tests passed.

## Known Gaps Before Regulated Production

- Add WORM storage or external notarization.
- Add managed RBAC, virtual keys, SSO, and policy signing.
- Add signed inventory provenance and authoritative owner/RBAC registry.
- Add CI/CD security review and AIBOM evidence.
