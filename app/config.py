from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_CONFIG: dict[str, Any] = {
    "server": {"port": 8080, "dashboard": True},
    "upstreams": [
        {"match": "gpt-*", "provider": "openai", "base_url": "https://api.openai.com"},
        {"match": "claude-*", "provider": "anthropic", "base_url": "https://api.anthropic.com"},
    ],
    "policy": {
        "on_error": "fail_open",
        "input": {
            "prompt_injection": {"action": "block", "threshold": 0.8},
            "pii": {"action": "flag", "threshold": 0.5},
            "secrets": {"action": "block", "threshold": 0.5},
        },
        "output": {
            "pii": {"action": "redact", "threshold": 0.5},
            "secrets": {"action": "block", "threshold": 0.5},
            "system_prompt_leakage": {"action": "block", "threshold": 0.8},
            "improper_output": {"action": "flag", "threshold": 0.8},
        },
    },
    "audit": {"store": "./data/audit.db", "retention_days": 90},
    "agent_firewall": {
        "enabled": True,
        "default_decision": "approval_required",
        "egress_allowlist": ["api.stripe.com", "api.sendgrid.com", "*.company.internal"],
        "blocked_egress": ["169.254.169.254", "localhost", "127.0.0.1", "::1"],
        "high_risk_actions": [
            "create_*",
            "update_*",
            "delete_*",
            "send_*",
            "transfer_*",
            "purchase*",
            "payment*",
        ],
        "approval": {"required_for_risk": ["high", "critical"], "ttl_seconds": 3600},
        "circuit_breaker": {
            "enabled": True,
            "kill_switch": False,
            "max_tool_calls_per_minute": 60,
            "max_blocked_calls_per_minute": 10,
        },
        "inventory": [
            {
                "name": "stripe.create_payment",
                "owner": "finance-platform",
                "category": "api",
                "risk": "high",
                "permissions": ["payments:create"],
                "data_access": ["customer_id", "amount", "currency"],
                "egress": ["api.stripe.com"],
                "allowed_agents": ["finance-assistant"],
                "approval_required": True,
            },
            {
                "name": "sendgrid.send_email",
                "owner": "growth-platform",
                "category": "api",
                "risk": "medium",
                "permissions": ["email:send"],
                "data_access": ["email", "template_id"],
                "egress": ["api.sendgrid.com"],
                "allowed_agents": ["support-assistant", "finance-assistant"],
                "approval_required": False,
            },
        ],
    },
    "framework_adapters": {
        "enabled": True,
        "adapters": ["langgraph", "crewai", "llamaindex"],
        "context_hooks": {
            "memory_write": {"enabled": True, "source_direction": "input", "add_context_mapping": True},
            "retrieval_context": {"enabled": True, "source_direction": "input", "add_context_mapping": True},
        },
        "discovery": {
            "enabled": True,
            "roots": [".", ".agents", ".codex"],
            "max_depth": 5,
            "max_files": 5000,
        },
        "catalog": {
            "enabled": True,
            "include_builtin": True,
        },
    },
}

VALID_ACTIONS = {"block", "redact", "flag", "off"}
VALID_ERROR_MODES = {"fail_open", "fail_closed"}
VALID_PROVIDERS = {"openai", "anthropic"}
VALID_SCANNER_ENGINES = {"auto", "regex", "presidio", "llm_guard"}
VALID_FIREWALL_DECISIONS = {"allow", "block", "approval_required"}
VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}
VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
VALID_FRAMEWORK_ADAPTERS = {"langgraph", "crewai", "llamaindex", "generic"}
VALID_CONTEXT_HOOKS = {"memory_write", "retrieval_context"}
VALID_CONTEXT_DIRECTIONS = {"input", "output"}


@dataclass(frozen=True)
class ServerConfig:
    port: int = 8080
    dashboard: bool = True


@dataclass(frozen=True)
class UpstreamConfig:
    match: str
    provider: str
    base_url: str


@dataclass(frozen=True)
class ScannerRule:
    action: str = "off"
    threshold: float = 1.0
    engine: str = "auto"
    timeout_ms: int = 250
    cascade: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyConfig:
    on_error: str = "fail_open"
    input: dict[str, ScannerRule] = field(default_factory=dict)
    output: dict[str, ScannerRule] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditConfig:
    store: str = "./data/audit.db"
    retention_days: int = 90


@dataclass(frozen=True)
class AgentApprovalConfig:
    required_for_risk: tuple[str, ...] = ("high", "critical")
    ttl_seconds: int = 3600


@dataclass(frozen=True)
class AgentCircuitBreakerConfig:
    enabled: bool = True
    kill_switch: bool = False
    max_tool_calls_per_minute: int = 60
    max_blocked_calls_per_minute: int = 10


@dataclass(frozen=True)
class ToolInventoryItem:
    name: str
    owner: str
    category: str = "tool"
    risk: str = "medium"
    permissions: tuple[str, ...] = ()
    data_access: tuple[str, ...] = ()
    egress: tuple[str, ...] = ()
    allowed_agents: tuple[str, ...] = ()
    approval_required: bool = False


@dataclass(frozen=True)
class AgentFirewallConfig:
    enabled: bool = True
    default_decision: str = "approval_required"
    egress_allowlist: tuple[str, ...] = ()
    blocked_egress: tuple[str, ...] = ("169.254.169.254", "localhost", "127.0.0.1", "::1")
    high_risk_actions: tuple[str, ...] = ()
    approval: AgentApprovalConfig = field(default_factory=AgentApprovalConfig)
    circuit_breaker: AgentCircuitBreakerConfig = field(default_factory=AgentCircuitBreakerConfig)
    inventory: tuple[ToolInventoryItem, ...] = ()


@dataclass(frozen=True)
class ContextHookConfig:
    enabled: bool = True
    source_direction: str = "input"
    add_context_mapping: bool = True


@dataclass(frozen=True)
class DiscoveryConfig:
    enabled: bool = True
    roots: tuple[str, ...] = (".", ".agents", ".codex")
    max_depth: int = 5
    max_files: int = 5000


@dataclass(frozen=True)
class InventoryCatalogConfig:
    enabled: bool = True
    include_builtin: bool = True


def _default_context_hooks() -> dict[str, ContextHookConfig]:
    return {
        "memory_write": ContextHookConfig(),
        "retrieval_context": ContextHookConfig(),
    }


@dataclass(frozen=True)
class FrameworkAdaptersConfig:
    enabled: bool = True
    adapters: tuple[str, ...] = ("langgraph", "crewai", "llamaindex")
    context_hooks: dict[str, ContextHookConfig] = field(default_factory=_default_context_hooks)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    catalog: InventoryCatalogConfig = field(default_factory=InventoryCatalogConfig)


@dataclass(frozen=True)
class AppConfig:
    server: ServerConfig
    upstreams: list[UpstreamConfig]
    policy: PolicyConfig
    audit: AuditConfig
    agent_firewall: AgentFirewallConfig = field(default_factory=AgentFirewallConfig)
    framework_adapters: FrameworkAdaptersConfig = field(default_factory=FrameworkAdaptersConfig)

    def match_upstream(self, model: str, default_provider: str) -> UpstreamConfig:
        for upstream in self.upstreams:
            if fnmatch(model, upstream.match):
                return upstream

        for upstream in self.upstreams:
            if upstream.provider == default_provider:
                return upstream

        raise ValueError(f"No upstream configured for model={model!r} provider={default_provider!r}")


def load_config(path: str | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("AMBY_CONFIG", "config.yaml"))
    raw = copy.deepcopy(DEFAULT_CONFIG)

    if config_path.exists():
        raw = _deep_merge(raw, _read_yaml(config_path))

    if os.getenv("AMBY_AUDIT_STORE"):
        raw.setdefault("audit", {})["store"] = os.environ["AMBY_AUDIT_STORE"]

    if os.getenv("PORT"):
        raw.setdefault("server", {})["port"] = int(os.environ["PORT"])

    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> AppConfig:
    if not isinstance(raw, dict):
        raise ValueError("Config must be a YAML object")

    server_raw = raw.get("server", {})
    audit_raw = raw.get("audit", {})
    policy_raw = raw.get("policy", {})
    firewall_raw = raw.get("agent_firewall", {})
    framework_raw = raw.get("framework_adapters", {})
    if not isinstance(server_raw, dict):
        raise ValueError("server config must be an object")
    if not isinstance(audit_raw, dict):
        raise ValueError("audit config must be an object")
    if not isinstance(policy_raw, dict):
        raise ValueError("policy config must be an object")
    if not isinstance(firewall_raw, dict):
        raise ValueError("agent_firewall config must be an object")
    if not isinstance(framework_raw, dict):
        raise ValueError("framework_adapters config must be an object")

    on_error = str(policy_raw.get("on_error", "fail_open"))
    if on_error not in VALID_ERROR_MODES:
        raise ValueError(f"Invalid policy.on_error={on_error!r}")

    upstreams_raw = raw.get("upstreams", [])
    if not isinstance(upstreams_raw, list):
        raise ValueError("upstreams config must be a list")
    upstreams = [_parse_upstream(item, index) for index, item in enumerate(upstreams_raw)]
    if not upstreams:
        raise ValueError("At least one upstream must be configured")

    port = int(server_raw.get("port", 8080))
    if port < 1 or port > 65535:
        raise ValueError(f"server.port must be between 1 and 65535: {port}")
    retention_days = int(audit_raw.get("retention_days", 90))
    if retention_days < 1:
        raise ValueError(f"audit.retention_days must be >= 1: {retention_days}")
    audit_store = str(audit_raw.get("store", "./data/audit.db"))
    if not audit_store:
        raise ValueError("audit.store must not be empty")

    return AppConfig(
        server=ServerConfig(
            port=port,
            dashboard=bool(server_raw.get("dashboard", True)),
        ),
        upstreams=upstreams,
        policy=PolicyConfig(
            on_error=on_error,
            input=_parse_direction_policy(policy_raw.get("input", {})),
            output=_parse_direction_policy(policy_raw.get("output", {})),
        ),
        audit=AuditConfig(
            store=audit_store,
            retention_days=retention_days,
        ),
        agent_firewall=_parse_agent_firewall(firewall_raw),
        framework_adapters=_parse_framework_adapters(framework_raw),
    )


def _parse_upstream(item: Any, index: int) -> UpstreamConfig:
    if not isinstance(item, dict):
        raise ValueError(f"upstreams[{index}] must be an object")
    match = str(item.get("match", "")).strip()
    provider = str(item.get("provider", "")).strip()
    base_url = str(item.get("base_url", "")).strip().rstrip("/")
    if not match:
        raise ValueError(f"upstreams[{index}].match must not be empty")
    if provider not in VALID_PROVIDERS:
        raise ValueError(f"upstreams[{index}].provider must be one of {sorted(VALID_PROVIDERS)}: {provider!r}")
    parsed_url = urlparse(base_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError(f"upstreams[{index}].base_url must be an http(s) URL: {base_url!r}")
    return UpstreamConfig(match=match, provider=provider, base_url=base_url)


def _parse_direction_policy(raw: dict[str, Any]) -> dict[str, ScannerRule]:
    if not isinstance(raw, dict):
        raise ValueError("policy direction config must be an object")
    parsed: dict[str, ScannerRule] = {}
    for scanner_name, rule_raw in raw.items():
        if not isinstance(rule_raw, dict):
            raise ValueError(f"Policy rule for {scanner_name} must be an object")
        action = str(rule_raw.get("action", "off"))
        if action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action for {scanner_name}: {action!r}")
        threshold = float(rule_raw.get("threshold", 1.0))
        if threshold < 0 or threshold > 1:
            raise ValueError(f"Invalid threshold for {scanner_name}: {threshold!r}")
        engine = str(rule_raw.get("engine", "auto"))
        if engine not in VALID_SCANNER_ENGINES:
            raise ValueError(f"Invalid engine for {scanner_name}: {engine!r}")
        timeout_ms = int(rule_raw.get("timeout_ms", 250))
        if timeout_ms < 1:
            raise ValueError(f"Invalid timeout_ms for {scanner_name}: {timeout_ms!r}")
        cascade_raw = rule_raw.get("cascade", ())
        if cascade_raw in (None, ""):
            cascade: tuple[str, ...] = ()
        elif isinstance(cascade_raw, str):
            cascade = (cascade_raw,)
        elif isinstance(cascade_raw, (list, tuple)):
            cascade = tuple(str(item) for item in cascade_raw)
        else:
            raise ValueError(f"Invalid cascade for {scanner_name}: {cascade_raw!r}")
        for item in cascade:
            if item not in VALID_SCANNER_ENGINES - {"auto"}:
                raise ValueError(f"Invalid cascade engine for {scanner_name}: {item!r}")
        parsed[str(scanner_name)] = ScannerRule(action=action, threshold=threshold, engine=engine, timeout_ms=timeout_ms, cascade=cascade)
    return parsed


def _parse_agent_firewall(raw: dict[str, Any]) -> AgentFirewallConfig:
    default_decision = str(raw.get("default_decision", "approval_required"))
    if default_decision not in VALID_FIREWALL_DECISIONS:
        raise ValueError(f"Invalid agent_firewall.default_decision={default_decision!r}")

    approval_raw = raw.get("approval", {})
    if not isinstance(approval_raw, dict):
        raise ValueError("agent_firewall.approval must be an object")
    required_for_risk = _parse_string_tuple(
        approval_raw.get("required_for_risk", ("high", "critical")),
        "agent_firewall.approval.required_for_risk",
    )
    for risk in required_for_risk:
        if risk not in VALID_RISK_LEVELS:
            raise ValueError(f"Invalid agent_firewall.approval.required_for_risk value={risk!r}")
    ttl_seconds = int(approval_raw.get("ttl_seconds", 3600))
    if ttl_seconds < 1:
        raise ValueError("agent_firewall.approval.ttl_seconds must be >= 1")

    breaker_raw = raw.get("circuit_breaker", {})
    if not isinstance(breaker_raw, dict):
        raise ValueError("agent_firewall.circuit_breaker must be an object")
    max_tool_calls = int(breaker_raw.get("max_tool_calls_per_minute", 60))
    max_blocked_calls = int(breaker_raw.get("max_blocked_calls_per_minute", 10))
    if max_tool_calls < 1:
        raise ValueError("agent_firewall.circuit_breaker.max_tool_calls_per_minute must be >= 1")
    if max_blocked_calls < 1:
        raise ValueError("agent_firewall.circuit_breaker.max_blocked_calls_per_minute must be >= 1")

    inventory_raw = raw.get("inventory", ())
    if not isinstance(inventory_raw, (list, tuple)):
        raise ValueError("agent_firewall.inventory must be a list")

    return AgentFirewallConfig(
        enabled=bool(raw.get("enabled", True)),
        default_decision=default_decision,
        egress_allowlist=_parse_string_tuple(raw.get("egress_allowlist", ()), "agent_firewall.egress_allowlist"),
        blocked_egress=_parse_string_tuple(
            raw.get("blocked_egress", ("169.254.169.254", "localhost", "127.0.0.1", "::1")),
            "agent_firewall.blocked_egress",
        ),
        high_risk_actions=_parse_string_tuple(raw.get("high_risk_actions", ()), "agent_firewall.high_risk_actions"),
        approval=AgentApprovalConfig(required_for_risk=required_for_risk, ttl_seconds=ttl_seconds),
        circuit_breaker=AgentCircuitBreakerConfig(
            enabled=bool(breaker_raw.get("enabled", True)),
            kill_switch=bool(breaker_raw.get("kill_switch", False)),
            max_tool_calls_per_minute=max_tool_calls,
            max_blocked_calls_per_minute=max_blocked_calls,
        ),
        inventory=tuple(_parse_tool_inventory_item(item, index) for index, item in enumerate(inventory_raw)),
    )


def _parse_framework_adapters(raw: dict[str, Any]) -> FrameworkAdaptersConfig:
    adapters = _parse_string_tuple(raw.get("adapters", ("langgraph", "crewai", "llamaindex")), "framework_adapters.adapters")
    for adapter in adapters:
        if adapter not in VALID_FRAMEWORK_ADAPTERS:
            raise ValueError(f"Invalid framework_adapters.adapters value={adapter!r}")

    hooks_raw = raw.get("context_hooks", {})
    if not isinstance(hooks_raw, dict):
        raise ValueError("framework_adapters.context_hooks must be an object")
    hooks: dict[str, ContextHookConfig] = {}
    for hook_name, hook_raw in hooks_raw.items():
        if hook_name not in VALID_CONTEXT_HOOKS:
            raise ValueError(f"Invalid framework_adapters.context_hooks key={hook_name!r}")
        if not isinstance(hook_raw, dict):
            raise ValueError(f"framework_adapters.context_hooks.{hook_name} must be an object")
        direction = str(hook_raw.get("source_direction", "input"))
        if direction not in VALID_CONTEXT_DIRECTIONS:
            raise ValueError(f"Invalid framework_adapters.context_hooks.{hook_name}.source_direction={direction!r}")
        hooks[hook_name] = ContextHookConfig(
            enabled=bool(hook_raw.get("enabled", True)),
            source_direction=direction,
            add_context_mapping=bool(hook_raw.get("add_context_mapping", True)),
        )
    for hook_name in VALID_CONTEXT_HOOKS:
        hooks.setdefault(hook_name, ContextHookConfig())

    discovery_raw = raw.get("discovery", {})
    if not isinstance(discovery_raw, dict):
        raise ValueError("framework_adapters.discovery must be an object")
    max_depth = int(discovery_raw.get("max_depth", 5))
    max_files = int(discovery_raw.get("max_files", 5000))
    if max_depth < 0:
        raise ValueError("framework_adapters.discovery.max_depth must be >= 0")
    if max_files < 1:
        raise ValueError("framework_adapters.discovery.max_files must be >= 1")

    catalog_raw = raw.get("catalog", {})
    if not isinstance(catalog_raw, dict):
        raise ValueError("framework_adapters.catalog must be an object")

    return FrameworkAdaptersConfig(
        enabled=bool(raw.get("enabled", True)),
        adapters=adapters,
        context_hooks=hooks,
        discovery=DiscoveryConfig(
            enabled=bool(discovery_raw.get("enabled", True)),
            roots=_parse_string_tuple(discovery_raw.get("roots", (".", ".agents", ".codex")), "framework_adapters.discovery.roots"),
            max_depth=max_depth,
            max_files=max_files,
        ),
        catalog=InventoryCatalogConfig(
            enabled=bool(catalog_raw.get("enabled", True)),
            include_builtin=bool(catalog_raw.get("include_builtin", True)),
        ),
    )


def _parse_tool_inventory_item(item: Any, index: int) -> ToolInventoryItem:
    if not isinstance(item, dict):
        raise ValueError(f"agent_firewall.inventory[{index}] must be an object")
    name = str(item.get("name", "")).strip()
    owner = str(item.get("owner", "")).strip()
    risk = str(item.get("risk", "medium")).strip()
    if not name:
        raise ValueError(f"agent_firewall.inventory[{index}].name must not be empty")
    if not owner:
        raise ValueError(f"agent_firewall.inventory[{index}].owner must not be empty")
    if risk not in VALID_RISK_LEVELS:
        raise ValueError(f"Invalid agent_firewall.inventory[{index}].risk={risk!r}")
    return ToolInventoryItem(
        name=name,
        owner=owner,
        category=str(item.get("category", "tool")).strip() or "tool",
        risk=risk,
        permissions=_parse_string_tuple(item.get("permissions", ()), f"agent_firewall.inventory[{index}].permissions"),
        data_access=_parse_string_tuple(item.get("data_access", ()), f"agent_firewall.inventory[{index}].data_access"),
        egress=_parse_string_tuple(item.get("egress", ()), f"agent_firewall.inventory[{index}].egress"),
        allowed_agents=_parse_string_tuple(item.get("allowed_agents", ()), f"agent_firewall.inventory[{index}].allowed_agents"),
        approval_required=bool(item.get("approval_required", False)),
    )


def _parse_string_tuple(raw: Any, path: str) -> tuple[str, ...]:
    if raw in (None, ""):
        return ()
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, (list, tuple)):
        parsed = tuple(str(item).strip() for item in raw if str(item).strip())
        return parsed
    raise ValueError(f"{path} must be a string or list of strings")


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyYAML is required to load config.yaml. Install the project dependencies.") from exc

    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Config file must contain a YAML object: {path}")
    return loaded


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(base[key], value)
        else:
            base[key] = value
    return base
