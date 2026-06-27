from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse
from typing import Any


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
        },
    },
    "audit": {"store": "./data/audit.db", "retention_days": 90},
}

VALID_ACTIONS = {"block", "redact", "flag", "off"}
VALID_ERROR_MODES = {"fail_open", "fail_closed"}
VALID_PROVIDERS = {"openai", "anthropic"}


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
class AppConfig:
    server: ServerConfig
    upstreams: list[UpstreamConfig]
    policy: PolicyConfig
    audit: AuditConfig

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
    if not isinstance(server_raw, dict):
        raise ValueError("server config must be an object")
    if not isinstance(audit_raw, dict):
        raise ValueError("audit config must be an object")
    if not isinstance(policy_raw, dict):
        raise ValueError("policy config must be an object")

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
        parsed[str(scanner_name)] = ScannerRule(action=action, threshold=threshold)
    return parsed


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
