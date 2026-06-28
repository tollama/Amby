from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.audit.store import AuditStore
from app.config import parse_config, policy_hash
from app.control_plane.service import (
    activate_policy_bundle,
    build_local_heartbeat,
    create_policy_bundle,
    evaluate_drift,
    sanitize_remote_heartbeat,
    verify_policy_bundle,
)
from app.control_plane.store import ControlPlaneStore
from app.main import create_app


RAW_SECRET = "sk-control-plane-raw-secret"


def _raw_config(tmp_path: Path, *, policy_action: str = "block", api_auth: bool = False) -> dict[str, object]:
    return {
        "server": {"port": 8080, "dashboard": True},
        "security": {
            "api_auth": {"enabled": api_auth, "token_env": "AMBY_API_TOKEN"},
            "dashboard_auth": {"enabled": False},
            "protect_sensitive_apis": True,
        },
        "control_plane": {
            "enabled": True,
            "node_id": "test-node",
            "policy_signing": {"enabled": True, "key_env": "AMBY_POLICY_SIGNING_KEY"},
            "heartbeat": {"enabled": True},
        },
        "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
        "policy": {"on_error": "fail_open", "input": {"prompt_injection": {"action": policy_action}}, "output": {}},
        "audit": {"store": str(tmp_path / "control.db"), "retention_days": 90},
        "predeploy": {"targets": {"api_key": RAW_SECRET}},
    }


def test_policy_bundle_signs_verifies_and_redacts_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AMBY_POLICY_SIGNING_KEY", RAW_SECRET)
    config = parse_config(_raw_config(tmp_path))
    store = ControlPlaneStore(config.audit.store)
    store.initialize()

    bundle = create_policy_bundle(config, store)

    assert verify_policy_bundle(bundle, RAW_SECRET) is True
    serialized = json.dumps(bundle, sort_keys=True)
    assert RAW_SECRET not in serialized
    assert "AMBY_POLICY_SIGNING_KEY" in serialized
    assert bundle["bundle"]["config_snapshot"]["predeploy"]["targets"]["api_key"] == "[REDACTED]"


def test_active_bundle_drift_detection_records_mismatch(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AMBY_POLICY_SIGNING_KEY", "policy-secret")
    config = parse_config(_raw_config(tmp_path, policy_action="block"))
    changed_config = parse_config(_raw_config(tmp_path, policy_action="flag"))
    store = ControlPlaneStore(config.audit.store)
    store.initialize()

    bundle = create_policy_bundle(config, store)
    activate_policy_bundle(store, bundle["id"], config=config)

    clean = evaluate_drift(config, store)
    drift = evaluate_drift(changed_config, store)

    assert clean["status"] == "clean"
    assert drift["status"] == "drift"
    assert drift["expected_policy_hash"] == policy_hash(config)
    assert drift["running_policy_hash"] == policy_hash(changed_config)
    assert store.list_drift_events()[0]["status"] == "drift"


def test_heartbeat_is_metadata_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AMBY_POLICY_SIGNING_KEY", "policy-secret")
    config = parse_config(_raw_config(tmp_path))
    audit_store = AuditStore(config.audit.store)
    audit_store.initialize()
    heartbeat = build_local_heartbeat(config, audit_store, diagnostics={"status": "ok"})

    assert heartbeat["node_id"] == "test-node"
    assert heartbeat["diagnostics_status"] == "ok"
    assert set(heartbeat["counts_summary"]) == {
        "audit_events",
        "tool_call_events",
        "context_events",
        "predeploy_runs",
        "predeploy_findings",
    }

    remote = sanitize_remote_heartbeat(
        {
            "node_id": "remote-node",
            "version": "0.1.0",
            "config_hash": "c" * 64,
            "policy_hash": "p" * 64,
            "diagnostics_status": "ok",
            "counts_summary": {"audit_events": 3, "raw_prompt": "ignore me"},
            "metadata": {"source": "agent", "raw_secret": RAW_SECRET, "environment": "pilot"},
            "raw_events": [{"prompt": "do not store"}],
        }
    )
    serialized = json.dumps(remote, sort_keys=True)
    assert RAW_SECRET not in serialized
    assert "do not store" not in serialized
    assert remote["counts_summary"]["audit_events"] == 3
    assert "raw_secret" not in remote["metadata"]


def test_control_plane_api_create_activate_drift_and_heartbeat(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AMBY_POLICY_SIGNING_KEY", "policy-secret")
    config = parse_config(_raw_config(tmp_path))
    client = TestClient(create_app(config))

    create_response = client.post("/control/policy-bundles", json={})
    assert create_response.status_code == 201
    bundle = create_response.json()
    assert bundle["status"] == "created"

    list_response = client.get("/control/policy-bundles")
    assert list_response.status_code == 200
    assert list_response.json()[0]["id"] == bundle["id"]

    activate_response = client.post(f"/control/policy-bundles/{bundle['id']}/activate")
    assert activate_response.status_code == 200
    assert activate_response.json()["status"] == "active"

    drift_response = client.get("/control/drift")
    assert drift_response.status_code == 200
    assert drift_response.json()["status"] == "clean"

    heartbeat_response = client.post("/control/fleet/heartbeat", json={})
    assert heartbeat_response.status_code == 201
    assert heartbeat_response.json()["node_id"] == "test-node"

    nodes_response = client.get("/control/fleet/nodes")
    assert nodes_response.status_code == 200
    assert nodes_response.json()["nodes"][0]["node_id"] == "test-node"


def test_control_plane_api_requires_auth_when_enabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AMBY_POLICY_SIGNING_KEY", "policy-secret")
    monkeypatch.setenv("AMBY_API_TOKEN", "api-secret")
    config = parse_config(_raw_config(tmp_path, api_auth=True))
    client = TestClient(create_app(config))

    assert client.get("/control/drift").status_code == 401
    assert client.get("/control/drift", headers={"x-amby-api-key": "api-secret"}).status_code == 200
