# Amby MVP

Amby is a local AI agent security and governance data plane. It sits in front of OpenAI-compatible and Anthropic-compatible model APIs, runs input/output guardrails, writes ASI-tagged audit events to SQLite, and generates tamper-evident evidence packages for CISO and audit review.

The current MVP is also a Mythos-ready seed control: it proves model-boundary guardrails, automated audit collection, ASI risk reporting, and evidence integrity. It does not claim to be a complete Mythos-ready security program yet; MCP/tool inventory, egress control, CI/CD security review, VulnOps, and automated response are roadmap items.

Source alignment: [CSA Labs - The AI Vulnerability Storm: Building a Mythos-ready Security Program](https://labs.cloudsecurityalliance.org/mythos-ciso/).

## Quickstart

```bash
docker build -t amby-mvp .
docker run --rm -p 8080:8080 \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  amby-mvp
```

Open `http://localhost:8080`, then click `Inject Demo` or run:

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
| Agent prompt/output harness defense | Partial | prompt injection, PII, and secrets guardrails |
| Agent adoption with oversight | Partial | model API policy/audit; tool and lifecycle controls pending |
| Environment hardening evidence | Partial | PII/secrets leakage detection; egress/MFA/segmentation integrations pending |
| Code/pipeline security review | Planned | Phase 2 CI runner, red-team results, SBOM/AIBOM |
| Agent/tool inventory | Planned | Phase 1 MCP/tool/plugin/skill inventory |
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
- `GET /audit/export?format=json|csv`: audit export.
- `POST /audit/evidence`: generate a local evidence package.
- `GET /stats/asi`: ASI distribution.
- `GET /stats/mythos`: Mythos-ready coverage and evidence matrix.
- `GET /stats/runtime`: runtime counts, scanner errors, and latency stats.
- `GET /events/stream`: live audit tail.
- `POST /demo/inject`: sample attack injector.
- `GET /`: local dashboard.

## Policy

Edit `config.yaml` to set scanner actions and thresholds.

```yaml
policy:
  on_error: fail_open
  input:
    prompt_injection: { action: block, threshold: 0.8 }
    pii: { action: flag, threshold: 0.5 }
    secrets: { action: block, threshold: 0.5 }
  output:
    pii: { action: redact, threshold: 0.5 }
    secrets: { action: block, threshold: 0.5 }
```

Actions are `block`, `redact`, `flag`, and `off`. Scanner errors are separate from detections; the default `fail_open` records the error and allows traffic.

## Scanner Engines

The MVP ships with deterministic local scanners for prompt-injection phrases, email/SSN PII, and common secret formats. If `presidio-analyzer` is installed, the PII scanner uses Microsoft Presidio automatically and falls back to regex scanning if unavailable.

The scanner registry is intentionally small and swappable so LLM Guard prompt-injection and secrets scanners can be wired in behind the same `Scanner` protocol without changing policy, audit, or proxy code.

## Privacy Defaults

Amby does not store raw prompts or responses. Audit rows contain scanner names, ASI tags, decisions, latency, masked snippets, and hashed client metadata. The only intended external network call is the configured upstream model API.

## Local Development

```bash
uv venv
uv pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8080
pytest
```

## Pilot Evidence

Korean financial-services pilot mapping is documented in [docs/korea_finance_evidence_sample.md](/Users/yongchoelchoi/Documents/Security/Amby/docs/korea_finance_evidence_sample.md). The minimum review bundle is `report.md`, `manifest.json`, `audit_chain.jsonl`, `config_snapshot.yaml`, and passing test output.
