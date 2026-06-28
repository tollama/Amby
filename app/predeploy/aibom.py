from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app import __version__
from app.config import AppConfig
from app.framework_adapters.discovery import discover_runtime_inventory


def generate_aibom(config: AppConfig, *, workspace_root: Path | None = None) -> dict[str, Any]:
    root = workspace_root or Path.cwd()
    inventory = discover_runtime_inventory(config.framework_adapters, workspace_root=root)
    pyproject = _read_pyproject(root / "pyproject.toml")
    package_json = _read_json(root / "package.json")
    prompt_config = root / str(config.predeploy.targets.get("promptfooconfig", "promptfooconfig.yaml"))

    aibom = {
        "schema_version": "amby.aibom.v1",
        "amby_version": __version__,
        "models": _model_components(config),
        "prompts": _prompt_components(root, prompt_config),
        "tools": _tool_components(config),
        "mcp_inventory": {
            "discovered_count": len(inventory.get("items", [])),
            "catalog_count": len(inventory.get("catalog", {}).get("items", [])),
            "items": inventory.get("items", []),
            "catalog": inventory.get("catalog", {}),
        },
        "framework_hooks": _framework_hooks(config),
        "scanner_engines": _scanner_engines(config),
        "dependencies": {
            "python": _python_dependencies(pyproject),
            "node": _node_dependencies(package_json),
        },
        "privacy": {
            "stores_raw_prompts": False,
            "stores_raw_model_outputs": False,
            "stores_raw_secrets": False,
            "notes": "AIBOM contains metadata, hashes, file paths, component names, and environment variable key names only.",
        },
        "counts": {},
        "sources": {
            "garak": "https://github.com/NVIDIA/garak",
            "pyrit": "https://github.com/Azure/PyRIT",
            "promptfoo": "https://www.promptfoo.dev/docs/installation/",
        },
    }
    aibom["counts"] = _counts(aibom)
    return aibom


def aibom_component_count(aibom: dict[str, Any]) -> int:
    counts = aibom.get("counts", {})
    return sum(int(value) for key, value in counts.items() if key.endswith("_count"))


def _model_components(config: AppConfig) -> list[dict[str, Any]]:
    models = []
    for upstream in config.upstreams:
        parsed = urlparse(upstream.base_url)
        models.append(
            {
                "match": upstream.match,
                "provider": upstream.provider,
                "base_url_host": parsed.netloc,
                "base_url_scheme": parsed.scheme,
            }
        )
    target_model = config.predeploy.targets.get("model")
    if target_model:
        models.append({"match": str(target_model), "provider": "predeploy-target", "base_url_host": None, "base_url_scheme": None})
    return models


def _prompt_components(root: Path, prompt_config: Path) -> list[dict[str, Any]]:
    prompts: list[dict[str, Any]] = []
    if prompt_config.exists() and prompt_config.is_file():
        prompts.append(_file_component(root, prompt_config, component_type="prompt_config"))
    prompts_root = root / "predeploy" / "promptfoo" / "prompts"
    if prompts_root.exists():
        for path in sorted(prompts_root.rglob("*")):
            if path.is_file():
                prompts.append(_file_component(root, path, component_type="prompt_case"))
    return prompts


def _tool_components(config: AppConfig) -> list[dict[str, Any]]:
    tools = []
    for item in config.agent_firewall.inventory:
        tools.append(
            {
                "name": item.name,
                "owner": item.owner,
                "category": item.category,
                "risk": item.risk,
                "permissions": list(item.permissions),
                "data_access": list(item.data_access),
                "egress": list(item.egress),
                "allowed_agents": list(item.allowed_agents),
                "approval_required": item.approval_required,
            }
        )
    return tools


def _framework_hooks(config: AppConfig) -> list[dict[str, Any]]:
    return [
        {
            "frameworks": list(config.framework_adapters.adapters),
            "hook_type": name,
            "enabled": hook.enabled,
            "source_direction": hook.source_direction,
            "add_context_mapping": hook.add_context_mapping,
        }
        for name, hook in sorted(config.framework_adapters.context_hooks.items())
    ]


def _scanner_engines(config: AppConfig) -> list[dict[str, Any]]:
    engines = []
    for name, adapter in sorted(config.predeploy.adapters.items()):
        engines.append(
            {
                "name": name,
                "enabled": adapter.enabled,
                "command_name": adapter.command[0] if adapter.command else None,
                "output_format": adapter.output_format,
                "timeout_seconds": adapter.timeout_seconds,
            }
        )
    for direction, rules in (("input", config.policy.input), ("output", config.policy.output)):
        for name, rule in sorted(rules.items()):
            engines.append(
                {
                    "name": name,
                    "enabled": rule.action != "off",
                    "direction": direction,
                    "engine": rule.engine,
                    "action": rule.action,
                    "threshold": rule.threshold,
                    "cascade": list(rule.cascade),
                }
            )
    return engines


def _python_dependencies(pyproject: dict[str, Any]) -> dict[str, Any]:
    project = pyproject.get("project", {}) if isinstance(pyproject, dict) else {}
    optional = project.get("optional-dependencies", {}) if isinstance(project, dict) else {}
    return {
        "dependencies": _dependency_names(project.get("dependencies", [])),
        "optional_dependencies": {
            str(extra): _dependency_names(items)
            for extra, items in sorted(optional.items())
            if isinstance(items, list)
        },
    }


def _node_dependencies(package_json: dict[str, Any]) -> dict[str, Any]:
    return {
        "engines": package_json.get("engines", {}) if isinstance(package_json.get("engines"), dict) else {},
        "dependencies": _node_dependency_names(package_json.get("dependencies", {})),
        "dev_dependencies": _node_dependency_names(package_json.get("devDependencies", {})),
    }


def _dependency_names(items: Any) -> list[dict[str, str]]:
    if not isinstance(items, list):
        return []
    dependencies = []
    for item in items:
        if not isinstance(item, str):
            continue
        name = item.split(";", 1)[0].strip()
        for separator in ("<=", ">=", "==", "~=", "!=", "<", ">", "="):
            if separator in name:
                name = name.split(separator, 1)[0].strip()
                break
        dependencies.append({"name": name, "specifier": item})
    return dependencies


def _node_dependency_names(items: Any) -> list[dict[str, str]]:
    if not isinstance(items, dict):
        return []
    return [{"name": str(name), "specifier": str(specifier)} for name, specifier in sorted(items.items())]


def _file_component(root: Path, path: Path, *, component_type: str) -> dict[str, Any]:
    return {
        "type": component_type,
        "path": _relative_path(root, path),
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _counts(aibom: dict[str, Any]) -> dict[str, int]:
    return {
        "model_count": len(aibom.get("models", [])),
        "prompt_count": len(aibom.get("prompts", [])),
        "tool_count": len(aibom.get("tools", [])),
        "mcp_discovered_count": int(aibom.get("mcp_inventory", {}).get("discovered_count", 0)),
        "mcp_catalog_count": int(aibom.get("mcp_inventory", {}).get("catalog_count", 0)),
        "framework_hook_count": len(aibom.get("framework_hooks", [])),
        "scanner_engine_count": len(aibom.get("scanner_engines", [])),
        "python_dependency_count": len(aibom.get("dependencies", {}).get("python", {}).get("dependencies", [])),
        "node_dependency_count": len(aibom.get("dependencies", {}).get("node", {}).get("dependencies", []))
        + len(aibom.get("dependencies", {}).get("node", {}).get("dev_dependencies", [])),
    }


def _read_pyproject(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)

