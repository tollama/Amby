# Amby MVP

Amby is a local AI agent security and governance data plane. It sits in front of OpenAI-compatible and Anthropic-compatible model APIs, runs input/output guardrails, writes ASI-tagged audit events to SQLite, and generates tamper-evident evidence packages for CISO and audit review.

The current MVP is also a Mythos-ready seed control: it proves model-boundary guardrails, agent tool-call firewall decisions, automated audit collection, ASI risk reporting, and evidence integrity. It does not claim to be a complete Mythos-ready security program yet; framework adapters, CI/CD security review, VulnOps, and automated response remain roadmap items.

Source alignment: [CSA Labs - The AI Vulnerability Storm: Building a Mythos-ready Security Program](https://labs.cloudsecurityalliance.org/mythos-ciso/).

## Quickstart

```bash
docker build -t amby-mvp .
docker run --rm -p 8080:8080 \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  amby-mvp
```

Open `http://localhost:8080`, then click `Inject Demo` for model guardrails or `Tool Demo` for agent firewall evidence. You can also run:

```bash
python -m app.demo
```

The demo creates a prompt-injection input event and an output DLP event with a redacted email and synthetic SSN.

For a local proof run:

```bash
python -m app.demo
python -m app.evidence generate --out evidence
python -m app.evidence verify evidence/<timestamp>
```

For a pilot smoke run against a running gateway:

```bash
scripts/pilot_smoke.sh
```

## Evidence Package

Generate a reproducible proof package from the audit database:

```bash
python -m app.evidence generate --out evidence
```

This creates a timestamped directory containing:

- `report.md`: human-readable MVP evidence report.
- `manifest.json`: package metadata and manifest hash.
- `audit_events.jsonl`: canonical audit export.
- `audit_events.csv`: CSV audit export.
- `audit_chain.jsonl`: event-level hash chain.
- `tool_call_events.jsonl`: canonical agent firewall export.
- `tool_call_events.csv`: CSV agent firewall export.
- `tool_call_chain.jsonl`: tool-call hash chain.
- `config_snapshot.yaml`: policy/config snapshot.
- `mythos_ready.json`: CSA Mythos-ready control coverage and evidence matrix.
- `hashes.sha256`: file-level checksums.

Verify the package:

```bash
python -m app.evidence verify evidence/<timestamp>
```

The evidence package proves integrity after generation. Full WORM storage or external notarization should be added before formal compliance use.

The dashboard `Evidence` button calls `POST /audit/evidence`. Set `AMBY_EVIDENCE_DIR` to control where server-generated packages are written.

## Mythos-ready Coverage

Amby maps the CSA Mythos-ready program guidance into explicit product coverage states:

| Control area | MVP status | Evidence |
| --- | --- | --- |
| Automated audit data collection | Implemented | `audit_events.*`, `report.md`, `manifest.json` |
| AI-speed risk reporting | Implemented | decision counts, ASI counts, latency, hash-chain head |
| Agent prompt/output/tool harness defense | Implemented | prompt/output guardrails and tool-call firewall events |
| Agent adoption with oversight | Implemented | agent identity, tool scope, egress policy, and human approval evidence |
| Environment hardening evidence | Partial | PII/secrets leakage detection and egress policy; MFA/segmentation integrations pending |
| Code/pipeline security review | Planned | Phase 2 CI runner, red-team results, SBOM/AIBOM |
| Agent/tool inventory | Implemented | owner, permission, data access, risk, allowed agents, and egress scope |
| VulnOps, deception, automated response | Planned | Phase 2/3 modules |

Use `GET /stats/mythos` or the dashboard `Mythos Readiness` panel to inspect the same matrix at runtime.

## Drop-in Model Proxy

OpenAI-compatible clients:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="not-used-by-amby")
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

Anthropic-compatible clients should point `base_url` to `http://localhost:8080` and call `/v1/messages`.

Streaming responses with `stream: true` are buffered, scanned, and then emitted as SSE. This preserves DLP enforcement for streaming output, with true token-by-token inline streaming left for a later hardening phase.

## API

- `POST /v1/chat/completions`: OpenAI-compatible proxy.
- `POST /v1/messages`: Anthropic-compatible proxy.
- `GET /healthz`: health check.
- `GET /diagnostics`: startup config and local readiness diagnostics.
- `GET /audit/events`: paginated audit events.
- `GET /audit/export?format=json|csv&scope=guardrails|tool_calls|all`: audit export.
- `GET /agent/inventory`: agent tool inventory and egress policy.
- `GET /agent/tool-calls/events`: agent firewall action lineage.
- `POST /v1/agent/tool-calls/evaluate`: evaluate a tool call before dispatch.
- `POST /v1/agent/approvals/{approval_id}/approve`: approve a pending high-risk tool call.
- `POST /v1/agent/approvals/{approval_id}/deny`: deny a pending high-risk tool call.
- `POST /audit/evidence`: generate a local evidence package.
- `GET /stats/asi`: ASI distribution.
- `GET /stats/mythos`: Mythos-ready coverage and evidence matrix.
- `GET /stats/coverage`: OWASP/NIST implemented/planned coverage matrix.
- `GET /stats/runtime`: runtime counts, scanner errors, and latency stats.
- `GET /events/stream`: live audit tail.
- `POST /demo/inject`: sample attack injector.
- `POST /demo/tool-call`: sample high-risk tool-call injector.
- `GET /`: local dashboard.

## Policy

Edit `config.yaml` to set scanner actions and thresholds.

```yaml
policy:
  on_error: fail_open
  input:
    prompt_injection: { action: block, threshold: 0.8, engine: auto, timeout_ms: 250, cascade: [regex, llm_guard] }
    pii: { action: flag, threshold: 0.5, engine: auto, timeout_ms: 250 }
    secrets: { action: block, threshold: 0.5, engine: auto, timeout_ms: 250, cascade: [regex, llm_guard] }
  output:
    pii: { action: redact, threshold: 0.5, engine: auto, timeout_ms: 250 }
    secrets: { action: block, threshold: 0.5, engine: auto, timeout_ms: 250 }
    system_prompt_leakage: { action: block, threshold: 0.8, engine: regex, timeout_ms: 100 }
    improper_output: { action: flag, threshold: 0.8, engine: regex, timeout_ms: 100 }
```

Actions are `block`, `redact`, `flag`, and `off`. Scanner errors are separate from detections; the default `fail_open` records the error and allows traffic.

## Agent Firewall

Phase 1 adds a pre-dispatch tool-call firewall. Agent runtimes call `POST /v1/agent/tool-calls/evaluate` before executing a function/API/MCP-style tool. Amby returns `allow`, `block`, or `approval_required`, records a `tool_call_events` row, and creates a pending approval when a high-risk action needs a human.

```yaml
agent_firewall:
  enabled: true
  default_decision: approval_required
  egress_allowlist: [api.stripe.com, api.sendgrid.com, "*.company.internal"]
  blocked_egress: ["169.254.169.254", localhost, "127.0.0.1", "::1"]
  high_risk_actions: ["create_*", "update_*", "delete_*", "send_*", "transfer_*"]
  approval:
    required_for_risk: [high, critical]
    ttl_seconds: 3600
  circuit_breaker:
    enabled: true
    kill_switch: false
    max_tool_calls_per_minute: 60
    max_blocked_calls_per_minute: 10
  inventory:
    - name: stripe.create_payment
      owner: finance-platform
      risk: high
      permissions: [payments:create]
      data_access: [customer_id, amount, currency]
      egress: [api.stripe.com]
      allowed_agents: [finance-assistant]
      approval_required: true
```

Tool-call detections map to OWASP LLM06 Excessive Agency, LLM10 Unbounded Consumption, ASI02/03/07/08, and NIST AI RMF GOVERN/MANAGE evidence.

## Scanner Engines

The MVP ships with deterministic local scanners for prompt-injection phrases, Korean/US PII, common secret formats, system prompt leakage, and improper output handling. If `presidio-analyzer` and `presidio-anonymizer` are installed, the PII scanner uses Microsoft Presidio automatically and falls back to regex scanning if unavailable.

The scanner registry is swappable: `engine: auto` can cascade deterministic regex scanners with optional LLM Guard prompt-injection and secrets scanners behind the same `Scanner` protocol. Use `timeout_ms` to keep slow scanners from dominating request latency.

Run the built-in scanner benchmark:

```bash
python -m app.guardrails.benchmark
```

## Privacy Defaults

Amby does not store raw prompts, responses, or tool arguments. Audit rows contain scanner/control names, ASI tags, decisions, latency, masked snippets or policy reasons, argument-key fingerprints, and hashed client metadata. The only intended external network call is the configured upstream model API; tool egress is evaluated before the agent dispatches the tool.

## Local Development

```bash
uv venv
uv pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8080
pytest
```

## Pilot Evidence

Korean financial-services pilot mapping is documented in [docs/korea_finance_evidence_sample.md](/Users/yongchoelchoi/Documents/Security/Amby/docs/korea_finance_evidence_sample.md). The minimum review bundle is `report.md`, `manifest.json`, `audit_chain.jsonl`, `config_snapshot.yaml`, and passing test output.
