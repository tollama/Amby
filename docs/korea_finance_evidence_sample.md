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
- `config_snapshot.yaml`: policy snapshot used for the pilot run.
- `hashes.sha256` and `manifest.json`: package integrity proof.

## Financial AI Governance Mapping

| Review concern | Amby MVP evidence | Status |
| --- | --- | --- |
| Transparency | Dashboard and report show each policy decision, scanner, ASI tag, and masked snippet. | Implemented |
| Human oversight / auxiliary use | MVP records model-boundary decisions; high-risk action approval is Phase 1. | Partial |
| Security | Prompt injection, PII, and secret leakage controls are enforced at the gateway. | Implemented |
| Reliability | Mock upstream E2E tests and pilot smoke script prove repeatable behavior without live model dependency. | Implemented |
| Access control | Client metadata is hashed; virtual keys/RBAC are Phase 1. | Partial |
| Data residency | Runtime audit and evidence generation stay local unless the configured upstream model API is called. | Implemented |
| Auditability | JSON/CSV export, hash chain, manifest hash, and config snapshot are generated per package. | Implemented |
| Change management | Policy snapshot is captured; signed policy bundles and drift detection are Phase 2.5. | Planned |

## Pilot Acceptance Evidence

Minimum evidence to attach to a pilot review:

1. `report.md` with event count, decision counts, ASI counts, and Mythos-ready coverage.
2. `manifest.json` with `manifest_hash`.
3. `audit_chain.jsonl` with a valid chain head.
4. `config_snapshot.yaml` showing scanner actions and thresholds.
5. Test output showing all E2E, privacy, scanner error, and evidence tests passed.

## Known Gaps Before Regulated Production

- Add WORM storage or external notarization.
- Add human approval for high-risk write actions.
- Add MCP/tool-call inventory and egress policy evidence.
- Add RBAC, virtual keys, SSO, and per-agent owner metadata.
- Add CI/CD security review and AIBOM evidence.
