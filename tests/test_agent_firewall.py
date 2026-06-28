from pathlib import Path

from fastapi.testclient import TestClient

from app.config import (
    AgentApprovalConfig,
    AgentCircuitBreakerConfig,
    AgentFirewallConfig,
    AppConfig,
    AuditConfig,
    PolicyConfig,
    ServerConfig,
    ToolInventoryItem,
    UpstreamConfig,
    parse_config,
)
from app.main import create_app


def _config(tmp_path: Path, firewall: AgentFirewallConfig) -> AppConfig:
    return AppConfig(
        server=ServerConfig(port=8080, dashboard=True),
        upstreams=[UpstreamConfig(match="gpt-*", provider="openai", base_url="https://mock.openai.local")],
        policy=PolicyConfig(on_error="fail_open", input={}, output={}),
        audit=AuditConfig(store=str(tmp_path / "audit.db"), retention_days=90),
        agent_firewall=firewall,
    )


def test_parse_config_accepts_agent_firewall_inventory() -> None:
    config = parse_config(
        {
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {"on_error": "fail_open", "input": {}, "output": {}},
            "audit": {"store": "./data/audit.db", "retention_days": 90},
            "agent_firewall": {
                "enabled": True,
                "default_decision": "approval_required",
                "egress_allowlist": ["api.stripe.com"],
                "approval": {"required_for_risk": ["high"], "ttl_seconds": 600},
                "circuit_breaker": {"max_tool_calls_per_minute": 10, "max_blocked_calls_per_minute": 3},
                "inventory": [
                    {
                        "name": "stripe.create_payment",
                        "owner": "finance-platform",
                        "risk": "high",
                        "egress": ["api.stripe.com"],
                        "allowed_agents": ["finance-assistant"],
                        "approval_required": True,
                    }
                ],
            },
        }
    )

    assert config.agent_firewall.inventory[0].name == "stripe.create_payment"
    assert config.agent_firewall.approval.ttl_seconds == 600


def test_high_risk_tool_call_requires_human_approval_then_allows_after_approval(tmp_path: Path) -> None:
    firewall = AgentFirewallConfig(
        default_decision="approval_required",
        egress_allowlist=("api.stripe.com",),
        high_risk_actions=("create_*",),
        approval=AgentApprovalConfig(required_for_risk=("high",), ttl_seconds=600),
        inventory=(
            ToolInventoryItem(
                name="stripe.create_payment",
                owner="finance-platform",
                risk="high",
                egress=("api.stripe.com",),
                allowed_agents=("finance-assistant",),
                approval_required=True,
            ),
        ),
    )
    client = TestClient(create_app(_config(tmp_path, firewall)))

    response = client.post(
        "/v1/agent/tool-calls/evaluate",
        json={
            "agent_id": "finance-assistant",
            "session_id": "session-1",
            "tool_name": "stripe.create_payment",
            "action": "create_payment",
            "method": "POST",
            "url": "https://api.stripe.com/v1/payment_intents?secret=not-stored",
            "arguments": {"customer_id": "cus_123", "amount": 1000},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "approval_required"
    assert payload["approval"]["status"] == "pending"
    assert payload["detections"][0]["llm_id"] == "LLM06"
    assert "secret=not-stored" not in payload["target"]

    approval_id = payload["approval_id"]
    approval = client.post(
        f"/v1/agent/approvals/{approval_id}/approve",
        json={"approver": "finance-manager", "comment": "Verified customer intent."},
    )
    assert approval.status_code == 200
    assert approval.json()["status"] == "approved"

    allowed = client.post(
        "/v1/agent/tool-calls/evaluate",
        json={
            "agent_id": "finance-assistant",
            "session_id": "session-1",
            "tool_name": "stripe.create_payment",
            "action": "create_payment",
            "method": "POST",
            "url": "https://api.stripe.com/v1/payment_intents",
            "approval_id": approval_id,
            "arguments": {"customer_id": "cus_123", "amount": 1000},
        },
    )

    assert allowed.status_code == 200
    assert allowed.json()["decision"] == "allow"
    events = client.get("/agent/tool-calls/events").json()
    assert [event["decision"] for event in reversed(events)] == ["approval_required", "allow"]
    assert events[0]["policy_snapshot"]["approval_status"] == "approved"
    exported = client.get("/audit/export?scope=tool_calls").json()
    assert exported[0]["approval_id"] == approval_id


def test_egress_and_agent_scope_violations_are_blocked(tmp_path: Path) -> None:
    firewall = AgentFirewallConfig(
        egress_allowlist=("api.stripe.com",),
        blocked_egress=("169.254.169.254",),
        approval=AgentApprovalConfig(required_for_risk=("high",), ttl_seconds=600),
        inventory=(
            ToolInventoryItem(
                name="stripe.create_payment",
                owner="finance-platform",
                risk="high",
                egress=("api.stripe.com",),
                allowed_agents=("finance-assistant",),
                approval_required=True,
            ),
        ),
    )
    client = TestClient(create_app(_config(tmp_path, firewall)))

    response = client.post(
        "/v1/agent/tool-calls/evaluate",
        json={
            "agent_id": "unknown-agent",
            "tool_name": "stripe.create_payment",
            "action": "create_payment",
            "method": "POST",
            "url": "http://169.254.169.254/latest/meta-data",
        },
    )

    payload = response.json()
    assert payload["decision"] == "block"
    assert {detection["asi_id"] for detection in payload["detections"]} == {"ASI03", "ASI07", "ASI02"}
    assert "target_host_blocked_by_egress_policy" in payload["reasons"]


def test_tool_call_rate_limit_records_llm10_block(tmp_path: Path) -> None:
    firewall = AgentFirewallConfig(
        default_decision="block",
        egress_allowlist=("api.company.internal",),
        approval=AgentApprovalConfig(required_for_risk=("high",), ttl_seconds=600),
        circuit_breaker=AgentCircuitBreakerConfig(
            enabled=True,
            kill_switch=False,
            max_tool_calls_per_minute=1,
            max_blocked_calls_per_minute=10,
        ),
        inventory=(
            ToolInventoryItem(
                name="catalog.lookup",
                owner="commerce-platform",
                risk="low",
                egress=("api.company.internal",),
                allowed_agents=("support-assistant",),
            ),
        ),
    )
    client = TestClient(create_app(_config(tmp_path, firewall)))
    body = {
        "agent_id": "support-assistant",
        "tool_name": "catalog.lookup",
        "action": "lookup",
        "method": "GET",
        "url": "https://api.company.internal/catalog/sku-1",
    }

    assert client.post("/v1/agent/tool-calls/evaluate", json=body).json()["decision"] == "allow"
    second = client.post("/v1/agent/tool-calls/evaluate", json=body).json()

    assert second["decision"] == "block"
    assert second["detections"][0]["llm_id"] == "LLM10"
    assert second["detections"][0]["asi_id"] == "ASI08"
