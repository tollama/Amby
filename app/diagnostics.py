from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from app import __version__
from app.config import AppConfig


def build_diagnostics(config: AppConfig) -> dict[str, Any]:
    checks = [
        _check("config_loaded", True, "Runtime config parsed successfully."),
        _check("upstreams_configured", bool(config.upstreams), f"{len(config.upstreams)} upstream route(s) configured."),
        _check("policy_configured", _has_enabled_policy(config), _policy_summary(config)),
        _check("audit_store_parent_writable", _audit_parent_writable(config.audit.store), _audit_store_detail(config.audit.store)),
        _check("dashboard_mode", config.server.dashboard, "Dashboard enabled." if config.server.dashboard else "Dashboard disabled."),
    ]
    return {
        "schema_version": "amby.diagnostics.v1",
        "amby_version": __version__,
        "status": "ok" if all(check["ok"] for check in checks if check["required"]) else "degraded",
        "server": {
            "port": config.server.port,
            "dashboard": config.server.dashboard,
        },
        "audit": {
            "store": config.audit.store,
            "retention_days": config.audit.retention_days,
        },
        "upstreams": [
            {
                "match": upstream.match,
                "provider": upstream.provider,
                "base_url": upstream.base_url,
            }
            for upstream in config.upstreams
        ],
        "policy": {
            "on_error": config.policy.on_error,
            "input_enabled": sorted(name for name, rule in config.policy.input.items() if rule.action != "off"),
            "output_enabled": sorted(name for name, rule in config.policy.output.items() if rule.action != "off"),
        },
        "checks": checks,
    }


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict[str, Any]:
    return {"name": name, "ok": ok, "required": required, "detail": detail}


def _has_enabled_policy(config: AppConfig) -> bool:
    return any(rule.action != "off" for rule in config.policy.input.values()) or any(
        rule.action != "off" for rule in config.policy.output.values()
    )


def _policy_summary(config: AppConfig) -> str:
    input_count = sum(1 for rule in config.policy.input.values() if rule.action != "off")
    output_count = sum(1 for rule in config.policy.output.values() if rule.action != "off")
    return f"{input_count} input scanner(s), {output_count} output scanner(s) enabled."


def _audit_parent_writable(store: str) -> bool:
    if store == ":memory:":
        return True
    parent = Path(store).expanduser().parent
    if parent.exists():
        return os.access(parent, os.W_OK)
    current = parent
    while not current.exists() and current != current.parent:
        current = current.parent
    return current.exists() and os.access(current, os.W_OK)


def _audit_store_detail(store: str) -> str:
    if store == ":memory:":
        return "Audit store is in-memory."
    parent = Path(store).expanduser().parent
    return f"Audit store parent: {parent}"
