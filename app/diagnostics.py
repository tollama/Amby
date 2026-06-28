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
        _check("agent_firewall_configured", config.agent_firewall.enabled, _agent_firewall_summary(config), required=False),
        _check("framework_adapters_configured", config.framework_adapters.enabled, _framework_adapters_summary(config), required=False),
        _check("predeploy_configured", config.predeploy.enabled, _predeploy_summary(config), required=False),
        _check("audit_store_parent_writable", _audit_parent_writable(config.audit.store), _audit_store_detail(config.audit.store)),
        _check("dashboard_mode", config.server.dashboard, "Dashboard enabled." if config.server.dashboard else "Dashboard disabled."),
    ]
    production_checks = _production_checks(config)
    production_ready = all(check["ok"] for check in production_checks)
    production_blocked = config.deployment.mode == "production" and not all(
        check["ok"] for check in production_checks if check["required"]
    )
    required_ok = all(check["ok"] for check in checks if check["required"])
    return {
        "schema_version": "amby.diagnostics.v1",
        "amby_version": __version__,
        "status": "blocked" if production_blocked else ("ok" if required_ok else "degraded"),
        "deployment": {
            "mode": config.deployment.mode,
            "production_ready": production_ready,
        },
        "server": {
            "port": config.server.port,
            "dashboard": config.server.dashboard,
        },
        "security": {
            "protect_sensitive_apis": config.security.protect_sensitive_apis,
            "dashboard_auth": _token_auth_summary(config.security.dashboard_auth),
            "api_auth": _token_auth_summary(config.security.api_auth),
        },
        "evidence": {
            "ledger": {
                "enabled": config.evidence.ledger.enabled,
                "path": config.evidence.ledger.path,
            },
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
            "scanner_rules": {
                **{f"input.{name}": _scanner_rule_summary(rule) for name, rule in config.policy.input.items()},
                **{f"output.{name}": _scanner_rule_summary(rule) for name, rule in config.policy.output.items()},
            },
        },
        "agent_firewall": {
            "enabled": config.agent_firewall.enabled,
            "default_decision": config.agent_firewall.default_decision,
            "egress_allowlist": list(config.agent_firewall.egress_allowlist),
            "blocked_egress": list(config.agent_firewall.blocked_egress),
            "high_risk_actions": list(config.agent_firewall.high_risk_actions),
            "approval": {
                "required_for_risk": list(config.agent_firewall.approval.required_for_risk),
                "ttl_seconds": config.agent_firewall.approval.ttl_seconds,
            },
            "circuit_breaker": {
                "enabled": config.agent_firewall.circuit_breaker.enabled,
                "kill_switch": config.agent_firewall.circuit_breaker.kill_switch,
                "max_tool_calls_per_minute": config.agent_firewall.circuit_breaker.max_tool_calls_per_minute,
                "max_blocked_calls_per_minute": config.agent_firewall.circuit_breaker.max_blocked_calls_per_minute,
            },
            "inventory_count": len(config.agent_firewall.inventory),
            "inventory": [
                {
                    "name": item.name,
                    "owner": item.owner,
                    "risk": item.risk,
                    "permissions": list(item.permissions),
                    "egress": list(item.egress),
                    "allowed_agents": list(item.allowed_agents),
                    "approval_required": item.approval_required,
                }
                for item in config.agent_firewall.inventory
            ],
        },
        "framework_adapters": {
            "enabled": config.framework_adapters.enabled,
            "adapters": list(config.framework_adapters.adapters),
            "context_hooks": {
                name: {
                    "enabled": hook.enabled,
                    "source_direction": hook.source_direction,
                    "add_context_mapping": hook.add_context_mapping,
                }
                for name, hook in config.framework_adapters.context_hooks.items()
            },
            "discovery": {
                "enabled": config.framework_adapters.discovery.enabled,
                "roots": list(config.framework_adapters.discovery.roots),
                "max_depth": config.framework_adapters.discovery.max_depth,
                "max_files": config.framework_adapters.discovery.max_files,
            },
            "catalog": {
                "enabled": config.framework_adapters.catalog.enabled,
                "include_builtin": config.framework_adapters.catalog.include_builtin,
            },
        },
        "predeploy": {
            "enabled": config.predeploy.enabled,
            "suite": config.predeploy.suite,
            "ci_gate": config.predeploy.ci_gate,
            "output_root": config.predeploy.output_root,
            "thresholds": {
                "max_fail_findings": config.predeploy.thresholds.max_fail_findings,
                "max_error_findings": config.predeploy.thresholds.max_error_findings,
                "max_warn_findings": config.predeploy.thresholds.max_warn_findings,
                "fail_on_adapter_error": config.predeploy.thresholds.fail_on_adapter_error,
            },
            "adapters": {
                name: {
                    "enabled": adapter.enabled,
                    "command_name": adapter.command[0] if adapter.command else None,
                    "arg_count": len(adapter.args),
                    "timeout_seconds": adapter.timeout_seconds,
                    "output_format": adapter.output_format,
                }
                for name, adapter in sorted(config.predeploy.adapters.items())
            },
            "target_keys": sorted(config.predeploy.targets),
        },
        "checks": checks,
        "production_checks": production_checks,
    }


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict[str, Any]:
    return {"name": name, "ok": ok, "required": required, "detail": detail}


def _production_checks(config: AppConfig) -> list[dict[str, Any]]:
    required = config.deployment.mode == "production"
    dashboard_token_present = _env_present(config.security.dashboard_auth.token_env)
    api_token_present = _env_present(config.security.api_auth.token_env)
    dashboard_protected = (not config.server.dashboard) or (
        config.security.dashboard_auth.enabled and dashboard_token_present
    )
    api_protected = (
        config.security.api_auth.enabled
        and config.security.protect_sensitive_apis
        and api_token_present
    )
    return [
        _check(
            "production_dashboard_auth",
            dashboard_protected,
            "Dashboard is disabled or protected by a configured token.",
            required=required,
        ),
        _check(
            "production_api_auth",
            api_protected,
            "Sensitive management APIs require a configured API token.",
            required=required,
        ),
        _check(
            "production_audit_persistence",
            config.audit.store != ":memory:",
            "Audit store is persistent.",
            required=required,
        ),
        _check(
            "production_evidence_ledger",
            config.evidence.ledger.enabled,
            "Evidence ledger is enabled.",
            required=required,
        ),
        _check(
            "production_predeploy_ci_gate",
            config.predeploy.enabled and config.predeploy.ci_gate,
            "Predeploy governance and CI gate are enabled.",
            required=required,
        ),
    ]


def _token_auth_summary(auth: Any) -> dict[str, Any]:
    return {
        "enabled": auth.enabled,
        "token_env": auth.token_env,
        "token_present": _env_present(auth.token_env),
    }


def _env_present(name: str) -> bool:
    return bool(name and os.getenv(name))


def _has_enabled_policy(config: AppConfig) -> bool:
    return any(rule.action != "off" for rule in config.policy.input.values()) or any(
        rule.action != "off" for rule in config.policy.output.values()
    )


def _policy_summary(config: AppConfig) -> str:
    input_count = sum(1 for rule in config.policy.input.values() if rule.action != "off")
    output_count = sum(1 for rule in config.policy.output.values() if rule.action != "off")
    return f"{input_count} input scanner(s), {output_count} output scanner(s) enabled."


def _agent_firewall_summary(config: AppConfig) -> str:
    state = "enabled" if config.agent_firewall.enabled else "disabled"
    return f"Agent firewall {state}; {len(config.agent_firewall.inventory)} inventoried tool(s)."


def _framework_adapters_summary(config: AppConfig) -> str:
    state = "enabled" if config.framework_adapters.enabled else "disabled"
    hooks = sum(1 for hook in config.framework_adapters.context_hooks.values() if hook.enabled)
    catalog_state = "catalog enabled" if config.framework_adapters.catalog.enabled else "catalog disabled"
    return f"Framework adapters {state}; {len(config.framework_adapters.adapters)} adapter(s), {hooks} context hook(s), {catalog_state}."


def _predeploy_summary(config: AppConfig) -> str:
    state = "enabled" if config.predeploy.enabled else "disabled"
    enabled_adapters = sum(1 for adapter in config.predeploy.adapters.values() if adapter.enabled)
    return f"Predeploy {state}; suite={config.predeploy.suite}; {enabled_adapters} adapter(s), CI gate={config.predeploy.ci_gate}."


def _scanner_rule_summary(rule: Any) -> dict[str, object]:
    return {
        "action": rule.action,
        "threshold": rule.threshold,
        "engine": rule.engine,
        "timeout_ms": rule.timeout_ms,
        "cascade": list(rule.cascade),
    }


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
