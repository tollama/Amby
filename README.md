# Amby MVP

Amby is a local AI agent security data plane. It sits in front of OpenAI-compatible and Anthropic-compatible model APIs, runs input/output guardrails, and writes ASI-tagged audit events to SQLite.

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

## API

- `POST /v1/chat/completions`: OpenAI-compatible proxy.
- `POST /v1/messages`: Anthropic-compatible proxy.
- `GET /healthz`: health check.
- `GET /audit/events`: paginated audit events.
- `GET /audit/export?format=json|csv`: audit export.
- `GET /stats/asi`: ASI distribution.
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
