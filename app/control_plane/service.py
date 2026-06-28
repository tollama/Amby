from __future__ import annotations

import hashlib
import os
import platform
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from app import __version__
from app.audit.store import AuditStore
from app.config import AppConfig, config_hash, policy_hash
from app.control_plane.signing import sign_payload, verify_signature
from app.control_plane.store import ControlPlaneStore


class ControlPlaneError(ValueError):
    pass


def policy_signing_key(config: AppConfig) -> str | None:
    if not config.control_plane.policy_signing.enabled:
        return None
    return os.getenv(config.control_plane.policy_signing.key_env)


def require_policy_signing_key(config: AppConfig) -> str:
    key = policy_signing_key(config)
    if not key:
        raise ControlPlaneError(
            f"Missing policy signing key environment variable: {config.control_plane.policy_signing.key_env}"
        )
    return key


def resolve_node_id(config: AppConfig) -> str:
    configured = config.control_plane.node_id.strip()
    if configured != "auto":
        return configured
    hostname = platform.node() or "unknown-host"
    digest = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:12]
    return f"amby-{digest}"


def create_policy_bundle(config: AppConfig, store: ControlPlaneStore, *, source: str = "current") -> dict[str, Any]:
    if not config.control_plane.enabled:
        raise ControlPlaneError("Control plane is disabled.")
    signing_key = require_policy_signing_key(config)
    created_at = datetime.now(UTC).isoformat()
    cfg_hash = config_hash(config)
    pol_hash = policy_hash(config)
    signing_payload = {
        "schema_version": "amby.policy_bundle.v1",
        "id": f"policy-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{pol_hash[:12]}-{uuid.uuid4().hex[:8]}",
        "created_at": created_at,
        "source": source,
        "node_id": resolve_node_id(config),
        "amby_version": __version__,
        "config_hash": cfg_hash,
        "policy_hash": pol_hash,
        "config_snapshot": sanitized_config_snapshot(config),
    }
    signature = sign_payload(signing_payload, signing_key)
    bundle = {
        "id": signing_payload["id"],
        "created_at": created_at,
        "activated_at": None,
        "source": source,
        "node_id": signing_payload["node_id"],
        "config_hash": cfg_hash,
        "policy_hash": pol_hash,
        "signature": signature,
        "signing_key_env": config.control_plane.policy_signing.key_env,
        "status": "created",
        "bundle": signing_payload,
    }
    return store.insert_policy_bundle(bundle)


def verify_policy_bundle(bundle_row: dict[str, Any], key: str) -> bool:
    bundle = bundle_row.get("bundle") or {}
    signature = str(bundle_row.get("signature") or "")
    return isinstance(bundle, dict) and verify_signature(bundle, key, signature)


def activate_policy_bundle(store: ControlPlaneStore, bundle_id: str, *, config: AppConfig | None = None) -> dict[str, Any]:
    bundle = store.get_policy_bundle(bundle_id)
    if bundle is None:
        raise ControlPlaneError(f"Policy bundle not found: {bundle_id}")
    if config is not None and config.control_plane.policy_signing.enabled:
        key = require_policy_signing_key(config)
        if not verify_policy_bundle(bundle, key):
            raise ControlPlaneError("Policy bundle signature verification failed.")
    activated = store.activate_policy_bundle(bundle_id)
    if activated is None:
        raise ControlPlaneError(f"Policy bundle not found: {bundle_id}")
    return activated


def build_local_heartbeat(
    config: AppConfig,
    audit_store: AuditStore,
    *,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "amby.fleet_heartbeat.v1",
        "node_id": resolve_node_id(config),
        "version": __version__,
        "config_hash": config_hash(config),
        "policy_hash": policy_hash(config),
        "diagnostics_status": str((diagnostics or {}).get("status") or "unknown"),
        "counts_summary": _runtime_counts(audit_store),
        "metadata": {
            "source": "local",
            "platform": platform.system(),
            "control_plane_enabled": config.control_plane.enabled,
        },
    }


def sanitize_remote_heartbeat(payload: dict[str, Any]) -> dict[str, Any]:
    counts = payload.get("counts_summary") if isinstance(payload.get("counts_summary"), dict) else {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    return {
        "schema_version": "amby.fleet_heartbeat.v1",
        "node_id": _required_str(payload, "node_id"),
        "version": _required_str(payload, "version"),
        "config_hash": _required_str(payload, "config_hash"),
        "policy_hash": _required_str(payload, "policy_hash"),
        "diagnostics_status": _required_str(payload, "diagnostics_status"),
        "counts_summary": _sanitize_count_summary(counts),
        "metadata": _sanitize_metadata(metadata),
    }


def evaluate_drift(config: AppConfig, store: ControlPlaneStore, *, record: bool = True) -> dict[str, Any]:
    running_config_hash = config_hash(config)
    running_policy_hash = policy_hash(config)
    active = store.active_policy_bundle()
    node_id = resolve_node_id(config)
    if active is None:
        drift_event = {
            "node_id": node_id,
            "active_bundle_id": None,
            "expected_config_hash": None,
            "running_config_hash": running_config_hash,
            "expected_policy_hash": None,
            "running_policy_hash": running_policy_hash,
            "severity": "info",
            "status": "no_active_bundle",
            "evidence": {"message": "No active expected policy bundle is configured."},
        }
    else:
        config_match = active.get("config_hash") == running_config_hash
        policy_match = active.get("policy_hash") == running_policy_hash
        status = "clean" if config_match and policy_match else "drift"
        drift_event = {
            "node_id": node_id,
            "active_bundle_id": active["id"],
            "expected_config_hash": active.get("config_hash"),
            "running_config_hash": running_config_hash,
            "expected_policy_hash": active.get("policy_hash"),
            "running_policy_hash": running_policy_hash,
            "severity": "info" if status == "clean" else "high",
            "status": status,
            "evidence": {
                "config_match": config_match,
                "policy_match": policy_match,
                "active_bundle_status": active.get("status"),
            },
        }
    stored_event = store.record_drift_event(drift_event) if record and drift_event["status"] != "clean" else None
    return {
        "schema_version": "amby.control_plane.drift.v1",
        "status": drift_event["status"],
        "drift": drift_event["status"] == "drift",
        "node_id": node_id,
        "active_bundle": _bundle_summary(active) if active else None,
        "running_config_hash": running_config_hash,
        "running_policy_hash": running_policy_hash,
        "expected_config_hash": drift_event.get("expected_config_hash"),
        "expected_policy_hash": drift_event.get("expected_policy_hash"),
        "severity": drift_event["severity"],
        "evidence": drift_event["evidence"],
        "recorded_event": stored_event,
    }


def build_control_plane_summary(config: AppConfig, store: ControlPlaneStore) -> dict[str, Any]:
    active = store.active_policy_bundle()
    drift = evaluate_drift(config, store, record=False)
    nodes = store.list_fleet_nodes()
    return {
        "schema_version": "amby.control_plane.summary.v1",
        "enabled": config.control_plane.enabled,
        "node_id": resolve_node_id(config),
        "policy_signing": {
            "enabled": config.control_plane.policy_signing.enabled,
            "key_env": config.control_plane.policy_signing.key_env,
            "key_present": bool(policy_signing_key(config)),
        },
        "active_bundle": _bundle_summary(active) if active else None,
        "drift": {
            "status": drift["status"],
            "severity": drift["severity"],
            "running_config_hash": drift["running_config_hash"],
            "running_policy_hash": drift["running_policy_hash"],
            "expected_config_hash": drift["expected_config_hash"],
            "expected_policy_hash": drift["expected_policy_hash"],
        },
        "fleet": {
            "node_count": len(nodes),
            "nodes": nodes,
        },
    }


def sanitized_config_snapshot(config: AppConfig) -> dict[str, Any]:
    return _sanitize_snapshot(asdict(config))


def _runtime_counts(audit_store: AuditStore) -> dict[str, int]:
    return {
        "audit_events": len(audit_store.export_events()),
        "tool_call_events": len(audit_store.export_tool_call_events()),
        "context_events": len(audit_store.export_context_events()),
        "predeploy_runs": len(audit_store.export_predeploy_runs()),
        "predeploy_findings": len(audit_store.export_predeploy_findings()),
    }


def _bundle_summary(bundle: dict[str, Any] | None) -> dict[str, Any] | None:
    if bundle is None:
        return None
    return {
        "id": bundle.get("id"),
        "status": bundle.get("status"),
        "created_at": bundle.get("created_at"),
        "activated_at": bundle.get("activated_at"),
        "node_id": bundle.get("node_id"),
        "config_hash": bundle.get("config_hash"),
        "policy_hash": bundle.get("policy_hash"),
        "signature": bundle.get("signature"),
        "signing_key_env": bundle.get("signing_key_env"),
    }


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise ControlPlaneError(f"heartbeat.{key} must not be empty")
    return value


def _sanitize_count_summary(value: dict[str, Any]) -> dict[str, int]:
    sanitized: dict[str, int] = {}
    for key, count in value.items():
        key_str = str(key)
        if not key_str:
            continue
        try:
            sanitized[key_str] = max(0, int(count))
        except (TypeError, ValueError):
            continue
    return sanitized


def _sanitize_metadata(value: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {"source", "platform", "region", "environment", "control_plane_enabled"}
    return {
        str(key): _sanitize_scalar(item)
        for key, item in value.items()
        if str(key) in allowed_keys
    }


def _sanitize_scalar(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return None
    return str(value)[:200]


def _sanitize_snapshot(value: Any, *, key_name: str = "") -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in sorted(value.items()):
            key_str = str(key)
            if _looks_secret_key(key_str):
                sanitized[key_str] = "[REDACTED]"
            else:
                sanitized[key_str] = _sanitize_snapshot(item, key_name=key_str)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize_snapshot(item, key_name=key_name) for item in value]
    if _looks_secret_key(key_name):
        return "[REDACTED]"
    return value


def _looks_secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in {"token_env", "key_env"}:
        return False
    secret_parts = ("secret", "token", "api_key", "apikey", "password", "credential", "private_key", "signing_key")
    return any(part in normalized for part in secret_parts)
