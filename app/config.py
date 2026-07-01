from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_CONFIG: dict[str, Any] = {
    "server": {"port": 8080, "dashboard": True},
    "deployment": {"mode": "development"},
    "security": {
        "dashboard_auth": {"enabled": False, "token_env": "AMBY_DASHBOARD_TOKEN"},
        "api_auth": {"enabled": False, "token_env": "AMBY_API_TOKEN"},
        "runtime_auth": {
            "enabled": False,
            "header_name": "x-amby-runtime-key",
            "keys": [
                {
                    "id": "local-runtime",
                    "token_env": "AMBY_RUNTIME_KEY",
                    "scopes": ["model_proxy", "agent_firewall", "framework_hooks"],
                    "allowed_models": ["*"],
                    "allowed_providers": ["openai", "anthropic"],
                    "max_requests_per_minute": 60,
                }
            ],
        },
        "protect_sensitive_apis": True,
    },
    "evidence": {
        "ledger": {"enabled": True, "path": "ledger.jsonl"},
    },
    "control_plane": {
        "enabled": True,
        "node_id": "auto",
        "policy_signing": {"enabled": True, "key_env": "AMBY_POLICY_SIGNING_KEY"},
        "heartbeat": {"enabled": True},
    },
    "upstreams": [
        {"match": "gpt-*", "provider": "openai", "base_url": "https://api.openai.com"},
        {"match": "claude-*", "provider": "anthropic", "base_url": "https://api.anthropic.com"},
    ],
    "proxy": {
        "block_response_format": "guardrail_error",
    },
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
    "predeploy": {
        "enabled": True,
        "suite": "default",
        "ci_gate": True,
        "output_root": "evidence/predeploy",
        "thresholds": {
            "max_fail_findings": 0,
            "max_error_findings": 0,
            "max_warn_findings": 999,
            "fail_on_adapter_error": True,
        },
        "targets": {
            "model": "gpt-*",
            "promptfooconfig": "promptfooconfig.yaml",
            "checks": [
                "prompt_injection",
                "leakage",
                "unsafe_tool_use",
                "rag_poisoning",
                "supply_chain_metadata",
            ],
        },
        "adapters": {
            "garak": {
                "enabled": True,
                "command": ["python", "-m", "garak"],
                "args": [],
                "timeout_seconds": 300,
                "output_format": "jsonl",
            },
            "pyrit": {
                "enabled": True,
                "command": ["pyrit_scan"],
                "args": [],
                "timeout_seconds": 300,
                "output_format": "json",
            },
            "promptfoo": {
                "enabled": True,
                "command": [
                    "npx",
                    "promptfoo",
                    "eval",
                    "-c",
                    "promptfooconfig.yaml",
                    "--no-table",
                    "--output",
                    ".amby-predeploy/promptfoo/results.json",
                ],
                "args": [],
                "timeout_seconds": 300,
                "output_format": "json",
            },
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
VALID_PREDEPLOY_ADAPTERS = {"garak", "pyrit", "promptfoo"}
VALID_PREDEPLOY_OUTPUT_FORMATS = {"auto", "json", "jsonl", "text"}
VALID_DEPLOYMENT_MODES = {"development", "pilot", "production"}
VALID_RUNTIME_AUTH_SCOPES = {"model_proxy", "agent_firewall", "framework_hooks"}
VALID_PROXY_BLOCK_RESPONSE_FORMATS = {"guardrail_error", "provider_shape"}


@dataclass(frozen=True)
class ServerConfig:
    port: int = 8080
    dashboard: bool = True


@dataclass(frozen=True)
class DeploymentConfig:
    mode: str = "development"


@dataclass(frozen=True)
class TokenAuthConfig:
    enabled: bool = False
    token_env: str = ""


@dataclass(frozen=True)
class RuntimeAuthKeyConfig:
    id: str
    token_env: str
    scopes: tuple[str, ...] = ("model_proxy", "agent_firewall", "framework_hooks")
    allowed_models: tuple[str, ...] = ("*",)
    allowed_providers: tuple[str, ...] = ("openai", "anthropic")
    max_requests_per_minute: int = 60


@dataclass(frozen=True)
class RuntimeAuthConfig:
    enabled: bool = False
    header_name: str = "x-amby-runtime-key"
    keys: tuple[RuntimeAuthKeyConfig, ...] = (
        RuntimeAuthKeyConfig(
            id="local-runtime",
            token_env="AMBY_RUNTIME_KEY",
        ),
    )


@dataclass(frozen=True)
class SecurityConfig:
    dashboard_auth: TokenAuthConfig = field(default_factory=lambda: TokenAuthConfig(token_env="AMBY_DASHBOARD_TOKEN"))
    api_auth: TokenAuthConfig = field(default_factory=lambda: TokenAuthConfig(token_env="AMBY_API_TOKEN"))
    runtime_auth: RuntimeAuthConfig = field(default_factory=RuntimeAuthConfig)
    protect_sensitive_apis: bool = True


@dataclass(frozen=True)
class EvidenceLedgerConfig:
    enabled: bool = True
    path: str = "ledger.jsonl"


@dataclass(frozen=True)
class EvidenceConfig:
    ledger: EvidenceLedgerConfig = field(default_factory=EvidenceLedgerConfig)


@dataclass(frozen=True)
class PolicySigningConfig:
    enabled: bool = True
    key_env: str = "AMBY_POLICY_SIGNING_KEY"


@dataclass(frozen=True)
class ControlPlaneHeartbeatConfig:
    enabled: bool = True


@dataclass(frozen=True)
class ControlPlaneConfig:
    enabled: bool = True
    node_id: str = "auto"
    policy_signing: PolicySigningConfig = field(default_factory=PolicySigningConfig)
    heartbeat: ControlPlaneHeartbeatConfig = field(default_factory=ControlPlaneHeartbeatConfig)


@dataclass(frozen=True)
class UpstreamConfig:
    match: str
    provider: str
    base_url: str


@dataclass(frozen=True)
class ProxyConfig:
    block_response_format: str = "guardrail_error"


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
class PredeployThresholdConfig:
    max_fail_findings: int = 0
    max_error_findings: int = 0
    max_warn_findings: int = 999
    fail_on_adapter_error: bool = True


@dataclass(frozen=True)
class PredeployAdapterConfig:
    enabled: bool = True
    command: tuple[str, ...] = ()
    args: tuple[str, ...] = ()
    timeout_seconds: int = 300
    output_format: str = "auto"


@dataclass(frozen=True)
class PredeployConfig:
    enabled: bool = True
    suite: str = "default"
    ci_gate: bool = True
    output_root: str = "evidence/predeploy"
    thresholds: PredeployThresholdConfig = field(default_factory=PredeployThresholdConfig)
    adapters: dict[str, PredeployAdapterConfig] = field(default_factory=dict)
    targets: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AppConfig:
    server: ServerConfig
    upstreams: list[UpstreamConfig]
    policy: PolicyConfig
    audit: AuditConfig
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    deployment: DeploymentConfig = field(default_factory=DeploymentConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    control_plane: ControlPlaneConfig = field(default_factory=ControlPlaneConfig)
    agent_firewall: AgentFirewallConfig = field(default_factory=AgentFirewallConfig)
    framework_adapters: FrameworkAdaptersConfig = field(default_factory=FrameworkAdaptersConfig)
    predeploy: PredeployConfig = field(default_factory=PredeployConfig)

    def match_upstream(self, model: str, default_provider: str) -> UpstreamConfig:
        for upstream in self.upstreams:
            if fnmatch(model, upstream.match):
                return upstream

        for upstream in self.upstreams:
            if upstream.provider == default_provider:
                return upstream

        raise ValueError(f"No upstream configured for model={model!r} provider={default_provider!r}")


def config_hash(config: AppConfig) -> str:
    return _hash_payload(_config_hash_payload(config))


def policy_hash(config: AppConfig) -> str:
    payload = _config_hash_payload(config)
    return _hash_payload(
        {
            "policy": payload["policy"],
            "agent_firewall": payload["agent_firewall"],
            "framework_adapters": payload["framework_adapters"],
            "predeploy": payload["predeploy"],
            "control_plane": payload["control_plane"],
        }
    )


def load_config(path: str | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("AMBY_CONFIG", "config.yaml"))
    raw = copy.deepcopy(DEFAULT_CONFIG)

    if config_path.exists():
        raw = _deep_merge(raw, _read_yaml(config_path))

    if os.getenv("AMBY_AUDIT_STORE"):
        raw.setdefault("audit", {})["store"] = os.environ["AMBY_AUDIT_STORE"]

    if os.getenv("PORT"):
        raw.setdefault("server", {})["port"] = int(os.environ["PORT"])

    if os.getenv("AMBY_DEPLOYMENT_MODE"):
        raw.setdefault("deployment", {})["mode"] = os.environ["AMBY_DEPLOYMENT_MODE"]

    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> AppConfig:
    if not isinstance(raw, dict):
        raise ValueError("Config must be a YAML object")

    server_raw = raw.get("server", {})
    deployment_raw = raw.get("deployment", {})
    security_raw = raw.get("security", {})
    evidence_raw = raw.get("evidence", {})
    control_plane_raw = raw.get("control_plane", {})
    audit_raw = raw.get("audit", {})
    proxy_raw = raw.get("proxy", {})
    policy_raw = raw.get("policy", {})
    firewall_raw = raw.get("agent_firewall", {})
    framework_raw = raw.get("framework_adapters", {})
    predeploy_raw = raw.get("predeploy", {})
    if not isinstance(server_raw, dict):
        raise ValueError("server config must be an object")
    if not isinstance(deployment_raw, dict):
        raise ValueError("deployment config must be an object")
    if not isinstance(security_raw, dict):
        raise ValueError("security config must be an object")
    if not isinstance(evidence_raw, dict):
        raise ValueError("evidence config must be an object")
    if not isinstance(control_plane_raw, dict):
        raise ValueError("control_plane config must be an object")
    if not isinstance(audit_raw, dict):
        raise ValueError("audit config must be an object")
    if not isinstance(proxy_raw, dict):
        raise ValueError("proxy config must be an object")
    if not isinstance(policy_raw, dict):
        raise ValueError("policy config must be an object")
    if not isinstance(firewall_raw, dict):
        raise ValueError("agent_firewall config must be an object")
    if not isinstance(framework_raw, dict):
        raise ValueError("framework_adapters config must be an object")
    if not isinstance(predeploy_raw, dict):
        raise ValueError("predeploy config must be an object")

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
        deployment=_parse_deployment(deployment_raw),
        security=_parse_security(security_raw),
        evidence=_parse_evidence(evidence_raw),
        control_plane=_parse_control_plane(control_plane_raw),
        upstreams=upstreams,
        proxy=_parse_proxy(proxy_raw),
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
        predeploy=_parse_predeploy(predeploy_raw),
    )


def _parse_proxy(raw: dict[str, Any]) -> ProxyConfig:
    block_response_format = str(raw.get("block_response_format", "guardrail_error")).strip()
    if block_response_format not in VALID_PROXY_BLOCK_RESPONSE_FORMATS:
        raise ValueError(
            f"Invalid proxy.block_response_format={block_response_format!r}; "
            f"must be one of {sorted(VALID_PROXY_BLOCK_RESPONSE_FORMATS)}"
        )
    return ProxyConfig(block_response_format=block_response_format)


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


def _parse_deployment(raw: dict[str, Any]) -> DeploymentConfig:
    mode = str(raw.get("mode", "development")).strip().lower()
    if mode not in VALID_DEPLOYMENT_MODES:
        raise ValueError(f"Invalid deployment.mode={mode!r}")
    return DeploymentConfig(mode=mode)


def _parse_security(raw: dict[str, Any]) -> SecurityConfig:
    dashboard_raw = raw.get("dashboard_auth", {})
    api_raw = raw.get("api_auth", {})
    runtime_raw = raw.get("runtime_auth", {})
    if not isinstance(dashboard_raw, dict):
        raise ValueError("security.dashboard_auth must be an object")
    if not isinstance(api_raw, dict):
        raise ValueError("security.api_auth must be an object")
    if not isinstance(runtime_raw, dict):
        raise ValueError("security.runtime_auth must be an object")
    return SecurityConfig(
        dashboard_auth=_parse_token_auth(dashboard_raw, default_env="AMBY_DASHBOARD_TOKEN", path="security.dashboard_auth"),
        api_auth=_parse_token_auth(api_raw, default_env="AMBY_API_TOKEN", path="security.api_auth"),
        runtime_auth=_parse_runtime_auth(runtime_raw),
        protect_sensitive_apis=bool(raw.get("protect_sensitive_apis", True)),
    )


def _parse_token_auth(raw: dict[str, Any], *, default_env: str, path: str) -> TokenAuthConfig:
    token_env = str(raw.get("token_env", default_env)).strip()
    if not token_env:
        raise ValueError(f"{path}.token_env must not be empty")
    return TokenAuthConfig(enabled=bool(raw.get("enabled", False)), token_env=token_env)


def _parse_runtime_auth(raw: dict[str, Any]) -> RuntimeAuthConfig:
    header_name = str(raw.get("header_name", "x-amby-runtime-key")).strip()
    if not header_name:
        raise ValueError("security.runtime_auth.header_name must not be empty")
    keys_raw = raw.get(
        "keys",
        [
            {
                "id": "local-runtime",
                "token_env": "AMBY_RUNTIME_KEY",
                "scopes": ["model_proxy", "agent_firewall", "framework_hooks"],
                "allowed_models": ["*"],
                "allowed_providers": ["openai", "anthropic"],
                "max_requests_per_minute": 60,
            }
        ],
    )
    if not isinstance(keys_raw, (list, tuple)):
        raise ValueError("security.runtime_auth.keys must be a list")
    keys = tuple(_parse_runtime_auth_key(item, index) for index, item in enumerate(keys_raw))
    ids = [key.id for key in keys]
    if len(set(ids)) != len(ids):
        raise ValueError("security.runtime_auth.keys ids must be unique")
    return RuntimeAuthConfig(
        enabled=bool(raw.get("enabled", False)),
        header_name=header_name,
        keys=keys,
    )


def _parse_runtime_auth_key(raw: Any, index: int) -> RuntimeAuthKeyConfig:
    if not isinstance(raw, dict):
        raise ValueError(f"security.runtime_auth.keys[{index}] must be an object")
    key_id = str(raw.get("id", "")).strip()
    if not key_id:
        raise ValueError(f"security.runtime_auth.keys[{index}].id must not be empty")
    token_env = str(raw.get("token_env", "")).strip()
    if not token_env:
        raise ValueError(f"security.runtime_auth.keys[{index}].token_env must not be empty")

    scopes = _parse_string_tuple(
        raw.get("scopes", ("model_proxy", "agent_firewall", "framework_hooks")),
        f"security.runtime_auth.keys[{index}].scopes",
    )
    if not scopes:
        raise ValueError(f"security.runtime_auth.keys[{index}].scopes must not be empty")
    for scope in scopes:
        if scope not in VALID_RUNTIME_AUTH_SCOPES:
            raise ValueError(f"Invalid security.runtime_auth.keys[{index}].scopes value={scope!r}")

    allowed_models = _parse_string_tuple(
        raw.get("allowed_models", ("*",)),
        f"security.runtime_auth.keys[{index}].allowed_models",
    )
    if not allowed_models:
        raise ValueError(f"security.runtime_auth.keys[{index}].allowed_models must not be empty")

    allowed_providers = _parse_string_tuple(
        raw.get("allowed_providers", ("openai", "anthropic")),
        f"security.runtime_auth.keys[{index}].allowed_providers",
    )
    if not allowed_providers:
        raise ValueError(f"security.runtime_auth.keys[{index}].allowed_providers must not be empty")
    for provider in allowed_providers:
        if provider not in VALID_PROVIDERS:
            raise ValueError(f"Invalid security.runtime_auth.keys[{index}].allowed_providers value={provider!r}")

    max_requests = int(raw.get("max_requests_per_minute", 60))
    if max_requests < 1:
        raise ValueError(f"security.runtime_auth.keys[{index}].max_requests_per_minute must be >= 1")

    return RuntimeAuthKeyConfig(
        id=key_id,
        token_env=token_env,
        scopes=scopes,
        allowed_models=allowed_models,
        allowed_providers=allowed_providers,
        max_requests_per_minute=max_requests,
    )


def _parse_evidence(raw: dict[str, Any]) -> EvidenceConfig:
    ledger_raw = raw.get("ledger", {})
    if not isinstance(ledger_raw, dict):
        raise ValueError("evidence.ledger must be an object")
    ledger_path = str(ledger_raw.get("path", "ledger.jsonl")).strip()
    if not ledger_path:
        raise ValueError("evidence.ledger.path must not be empty")
    return EvidenceConfig(
        ledger=EvidenceLedgerConfig(
            enabled=bool(ledger_raw.get("enabled", True)),
            path=ledger_path,
        )
    )


def _parse_control_plane(raw: dict[str, Any]) -> ControlPlaneConfig:
    signing_raw = raw.get("policy_signing", {})
    heartbeat_raw = raw.get("heartbeat", {})
    if not isinstance(signing_raw, dict):
        raise ValueError("control_plane.policy_signing must be an object")
    if not isinstance(heartbeat_raw, dict):
        raise ValueError("control_plane.heartbeat must be an object")
    node_id = str(raw.get("node_id", "auto")).strip()
    if not node_id:
        raise ValueError("control_plane.node_id must not be empty")
    key_env = str(signing_raw.get("key_env", "AMBY_POLICY_SIGNING_KEY")).strip()
    if not key_env:
        raise ValueError("control_plane.policy_signing.key_env must not be empty")
    return ControlPlaneConfig(
        enabled=bool(raw.get("enabled", True)),
        node_id=node_id,
        policy_signing=PolicySigningConfig(
            enabled=bool(signing_raw.get("enabled", True)),
            key_env=key_env,
        ),
        heartbeat=ControlPlaneHeartbeatConfig(enabled=bool(heartbeat_raw.get("enabled", True))),
    )


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


def _parse_predeploy(raw: dict[str, Any]) -> PredeployConfig:
    suite = str(raw.get("suite", "default")).strip()
    if not suite:
        raise ValueError("predeploy.suite must not be empty")
    output_root = str(raw.get("output_root", "evidence/predeploy")).strip()
    if not output_root:
        raise ValueError("predeploy.output_root must not be empty")

    thresholds_raw = raw.get("thresholds", {})
    if not isinstance(thresholds_raw, dict):
        raise ValueError("predeploy.thresholds must be an object")
    thresholds = PredeployThresholdConfig(
        max_fail_findings=_parse_nonnegative_int(thresholds_raw.get("max_fail_findings", 0), "predeploy.thresholds.max_fail_findings"),
        max_error_findings=_parse_nonnegative_int(thresholds_raw.get("max_error_findings", 0), "predeploy.thresholds.max_error_findings"),
        max_warn_findings=_parse_nonnegative_int(thresholds_raw.get("max_warn_findings", 999), "predeploy.thresholds.max_warn_findings"),
        fail_on_adapter_error=bool(thresholds_raw.get("fail_on_adapter_error", True)),
    )

    adapters_raw = raw.get("adapters", {})
    if not isinstance(adapters_raw, dict):
        raise ValueError("predeploy.adapters must be an object")
    adapters: dict[str, PredeployAdapterConfig] = {}
    for name, adapter_raw in adapters_raw.items():
        adapter_name = str(name).strip()
        if adapter_name not in VALID_PREDEPLOY_ADAPTERS:
            raise ValueError(f"Invalid predeploy.adapters key={adapter_name!r}")
        if not isinstance(adapter_raw, dict):
            raise ValueError(f"predeploy.adapters.{adapter_name} must be an object")
        adapters[adapter_name] = _parse_predeploy_adapter(adapter_name, adapter_raw)

    default_adapters = DEFAULT_CONFIG["predeploy"]["adapters"]
    for name, adapter_raw in default_adapters.items():
        adapters.setdefault(str(name), _parse_predeploy_adapter(str(name), adapter_raw))

    targets_raw = raw.get("targets", {})
    if targets_raw in (None, ""):
        targets: dict[str, Any] = {}
    elif isinstance(targets_raw, dict):
        targets = _sanitize_config_dict(targets_raw)
    else:
        raise ValueError("predeploy.targets must be an object")

    return PredeployConfig(
        enabled=bool(raw.get("enabled", True)),
        suite=suite,
        ci_gate=bool(raw.get("ci_gate", True)),
        output_root=output_root,
        thresholds=thresholds,
        adapters=adapters,
        targets=targets,
    )


def _parse_predeploy_adapter(name: str, raw: dict[str, Any]) -> PredeployAdapterConfig:
    command = _parse_string_tuple(raw.get("command", ()), f"predeploy.adapters.{name}.command")
    args = _parse_string_tuple(raw.get("args", ()), f"predeploy.adapters.{name}.args")
    timeout_seconds = int(raw.get("timeout_seconds", 300))
    if timeout_seconds < 1:
        raise ValueError(f"predeploy.adapters.{name}.timeout_seconds must be >= 1")
    output_format = str(raw.get("output_format", "auto")).strip()
    if output_format not in VALID_PREDEPLOY_OUTPUT_FORMATS:
        raise ValueError(f"Invalid predeploy.adapters.{name}.output_format={output_format!r}")
    return PredeployAdapterConfig(
        enabled=bool(raw.get("enabled", True)),
        command=command,
        args=args,
        timeout_seconds=timeout_seconds,
        output_format=output_format,
    )


def _parse_nonnegative_int(raw: Any, path: str) -> int:
    value = int(raw)
    if value < 0:
        raise ValueError(f"{path} must be >= 0")
    return value


def _sanitize_config_dict(raw: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in raw.items():
        key_str = str(key)
        if isinstance(value, dict):
            sanitized[key_str] = _sanitize_config_dict(value)
        elif isinstance(value, (list, tuple)):
            sanitized[key_str] = [
                _sanitize_config_dict(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            sanitized[key_str] = value
    return sanitized


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


def _config_hash_payload(config: AppConfig) -> dict[str, Any]:
    payload = asdict(config)
    return _sanitize_hash_payload(payload)


def _sanitize_hash_payload(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in sorted(value.items()):
            key_str = str(key)
            if _looks_sensitive_key(key_str):
                sanitized[key_str] = "[REDACTED]"
            else:
                sanitized[key_str] = _sanitize_hash_payload(item)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize_hash_payload(item) for item in value]
    return value


def _looks_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered == "token_env":
        return False
    return any(part in lowered for part in ("secret", "token", "api_key", "password", "credential"))


def _hash_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
