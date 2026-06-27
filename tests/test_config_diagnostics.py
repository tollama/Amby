from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import AppConfig, AuditConfig, PolicyConfig, ScannerRule, ServerConfig, UpstreamConfig, parse_config
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
    assert payload["upstreams"][0]["provider"] == "openai"
