import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import AppConfig, AuditConfig, PolicyConfig, ScannerRule, ServerConfig, UpstreamConfig, config_hash, parse_config, policy_hash
from app.diagnostics import build_diagnostics
from app.main import create_app


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        server=ServerConfig(port=8080, dashboard=True),
        upstreams=[UpstreamConfig(match="gpt-*", provider="openai", base_url="https://mock.openai.local")],
        policy=PolicyConfig(
            on_error="fail_open",
            input={"prompt_injection": ScannerRule(action="block", threshold=0.8)},
            output={"pii": ScannerRule(action="redact", threshold=0.5)},
        ),
        audit=AuditConfig(store=str(tmp_path / "audit.db"), retention_days=90),
    )


def test_parse_config_rejects_invalid_upstream_provider() -> None:
    with pytest.raises(ValueError, match="provider"):
        parse_config(
            {
                "upstreams": [{"match": "gpt-*", "provider": "unknown", "base_url": "https://example.com"}],
                "policy": {"on_error": "fail_open", "input": {}, "output": {}},
                "audit": {"store": "./data/audit.db", "retention_days": 90},
            }
        )


def test_parse_config_accepts_scanner_engine_timeout_and_cascade() -> None:
    config = parse_config(
        {
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {
                "on_error": "fail_open",
                "input": {
                    "prompt_injection": {
                        "action": "block",
                        "threshold": 0.8,
                        "engine": "auto",
                        "timeout_ms": 123,
                        "cascade": ["regex", "llm_guard"],
                    }
                },
                "output": {},
            },
            "audit": {"store": "./data/audit.db", "retention_days": 90},
        }
    )

    rule = config.policy.input["prompt_injection"]
    assert rule.engine == "auto"
    assert rule.timeout_ms == 123
    assert rule.cascade == ("regex", "llm_guard")


def test_parse_config_accepts_deployment_security_and_evidence() -> None:
    config = parse_config(
        {
            "deployment": {"mode": "pilot"},
            "security": {
                "dashboard_auth": {"enabled": True, "token_env": "DASH_TOKEN"},
                "api_auth": {"enabled": True, "token_env": "API_TOKEN"},
                "protect_sensitive_apis": True,
            },
            "evidence": {"ledger": {"enabled": True, "path": "review-ledger.jsonl"}},
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {"on_error": "fail_open", "input": {"prompt_injection": {"action": "block"}}, "output": {}},
            "audit": {"store": "./data/audit.db", "retention_days": 90},
        }
    )

    assert config.deployment.mode == "pilot"
    assert config.security.dashboard_auth.enabled is True
    assert config.security.dashboard_auth.token_env == "DASH_TOKEN"
    assert config.security.api_auth.enabled is True
    assert config.evidence.ledger.path == "review-ledger.jsonl"


def test_config_and_policy_hashes_are_stable_and_policy_sensitive() -> None:
    raw = {
        "deployment": {"mode": "production"},
        "security": {
            "dashboard_auth": {"enabled": True, "token_env": "DASH_TOKEN"},
            "api_auth": {"enabled": True, "token_env": "API_TOKEN"},
        },
        "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
        "policy": {"on_error": "fail_open", "input": {"prompt_injection": {"action": "block"}}, "output": {}},
        "audit": {"store": "./data/audit.db", "retention_days": 90},
    }
    config = parse_config(raw)
    same_config = parse_config(raw)
    changed_policy = parse_config(
        {
            **raw,
            "policy": {"on_error": "fail_open", "input": {"prompt_injection": {"action": "flag"}}, "output": {}},
        }
    )

    assert config_hash(config) == config_hash(same_config)
    assert policy_hash(config) == policy_hash(same_config)
    assert policy_hash(config) != policy_hash(changed_policy)


def test_parse_config_rejects_invalid_scanner_engine() -> None:
    with pytest.raises(ValueError, match="engine"):
        parse_config(
            {
                "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
                "policy": {
                    "on_error": "fail_open",
                    "input": {"prompt_injection": {"action": "block", "engine": "bogus"}},
                    "output": {},
                },
                "audit": {"store": "./data/audit.db", "retention_days": 90},
            }
        )


def test_parse_config_rejects_invalid_port_and_url() -> None:
    with pytest.raises(ValueError, match="server.port"):
        parse_config(
            {
                "server": {"port": 70000, "dashboard": True},
                "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
                "policy": {"on_error": "fail_open", "input": {}, "output": {}},
                "audit": {"store": "./data/audit.db", "retention_days": 90},
            }
        )
    with pytest.raises(ValueError, match="base_url"):
        parse_config(
            {
                "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "not-a-url"}],
                "policy": {"on_error": "fail_open", "input": {}, "output": {}},
                "audit": {"store": "./data/audit.db", "retention_days": 90},
            }
        )


def test_diagnostics_endpoint_reports_startup_config(tmp_path: Path) -> None:
    client = TestClient(create_app(_config(tmp_path)))

    response = client.get("/diagnostics")

    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "amby.diagnostics.v1"
    assert payload["status"] == "ok"
    assert payload["policy"]["input_enabled"] == ["prompt_injection"]
    assert payload["policy"]["scanner_rules"]["input.prompt_injection"]["engine"] == "auto"
    assert payload["framework_adapters"]["adapters"] == ["langgraph", "crewai", "llamaindex"]
    assert payload["framework_adapters"]["context_hooks"]["memory_write"]["enabled"] is True
    assert payload["framework_adapters"]["catalog"]["include_builtin"] is True
    assert payload["upstreams"][0]["provider"] == "openai"


def test_production_diagnostics_block_when_required_controls_missing(tmp_path: Path) -> None:
    config = parse_config(
        {
            "deployment": {"mode": "production"},
            "security": {
                "dashboard_auth": {"enabled": False},
                "api_auth": {"enabled": False},
            },
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {"on_error": "fail_open", "input": {}, "output": {}},
            "audit": {"store": str(tmp_path / "audit.db"), "retention_days": 90},
        }
    )

    payload = build_diagnostics(config)

    assert payload["deployment"]["mode"] == "production"
    assert payload["deployment"]["production_ready"] is False
    assert payload["status"] == "blocked"
    assert any(check["name"] == "production_api_auth" and not check["ok"] for check in payload["production_checks"])


def test_production_diagnostics_pass_with_tokens_and_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASH_TOKEN", "dashboard-secret")
    monkeypatch.setenv("API_TOKEN", "api-secret")
    config = parse_config(
        {
            "deployment": {"mode": "production"},
            "security": {
                "dashboard_auth": {"enabled": True, "token_env": "DASH_TOKEN"},
                "api_auth": {"enabled": True, "token_env": "API_TOKEN"},
            },
            "evidence": {"ledger": {"enabled": True, "path": str(tmp_path / "ledger.jsonl")}},
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {"on_error": "fail_open", "input": {"prompt_injection": {"action": "block"}}, "output": {}},
            "audit": {"store": str(tmp_path / "audit.db"), "retention_days": 90},
            "predeploy": {"enabled": True, "ci_gate": True},
        }
    )

    payload = build_diagnostics(config)

    assert payload["status"] == "ok"
    assert payload["deployment"]["production_ready"] is True
    assert payload["security"]["dashboard_auth"]["token_present"] is True
    assert payload["security"]["api_auth"]["token_present"] is True


def test_sensitive_api_auth_and_dashboard_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AMBY_API_TOKEN", "api-secret")
    monkeypatch.setenv("AMBY_DASHBOARD_TOKEN", "dashboard-secret")
    config = parse_config(
        {
            "security": {
                "dashboard_auth": {"enabled": True, "token_env": "AMBY_DASHBOARD_TOKEN"},
                "api_auth": {"enabled": True, "token_env": "AMBY_API_TOKEN"},
            },
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {"on_error": "fail_open", "input": {}, "output": {}},
            "audit": {"store": str(tmp_path / "audit.db"), "retention_days": 90},
        }
    )
    client = TestClient(create_app(config))

    assert client.get("/audit/events").status_code == 401
    assert client.get("/audit/events", headers={"x-amby-api-key": "api-secret"}).status_code == 200

    dashboard_blocked = client.get("/")
    assert dashboard_blocked.status_code == 401
    dashboard_allowed = client.get("/", headers={"authorization": "Bearer dashboard-secret"})
    assert dashboard_allowed.status_code == 200
    assert "amby_dashboard_token" in dashboard_allowed.headers.get("set-cookie", "")


def test_audit_export_jsonl_includes_event_type_and_hashes(tmp_path: Path) -> None:
    config = _config(tmp_path)
    client = TestClient(create_app(config))

    demo_response = client.post("/demo/inject")
    assert demo_response.status_code == 200
    response = client.get("/audit/export?format=jsonl&scope=all")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    rows = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    assert rows
    assert {row["event_type"] for row in rows} >= {"guardrail"}
    assert all(row["schema_version"] == "amby.audit_jsonl.v1" for row in rows)
    assert any(row.get("policy_hash") == policy_hash(config) for row in rows)
    assert any(row.get("config_hash") == config_hash(config) for row in rows)
