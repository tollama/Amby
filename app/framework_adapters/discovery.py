from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import FrameworkAdaptersConfig


SKIP_DIRS = {".git", ".venv", "__pycache__", "data", "evidence", ".pytest_cache"}
MCP_FILENAMES = {"mcp.json", ".mcp.json"}


@dataclass(frozen=True)
class DiscoveredInventoryItem:
    item_type: str
    name: str
    source: str
    owner: str = "unknown"
    risk: str = "medium"
    metadata: dict[str, object] | None = None


def discover_runtime_inventory(config: FrameworkAdaptersConfig, *, workspace_root: Path) -> dict[str, object]:
    if not config.enabled or not config.discovery.enabled:
        return {
            "schema_version": "amby.framework_inventory.v1",
            "enabled": False,
            "roots": [],
            "counts": {},
            "items": [],
        }

    root = workspace_root.resolve()
    items: list[DiscoveredInventoryItem] = []
    visited_files = 0
    visited_roots: list[str] = []
    for configured_root in config.discovery.roots:
        scan_root = _resolve_inside_root(root, configured_root)
        if scan_root is None or not scan_root.exists():
            continue
        visited_roots.append(str(scan_root))
        for path in _walk(scan_root, root=root, max_depth=config.discovery.max_depth):
            visited_files += 1
            if visited_files > config.discovery.max_files:
                break
            items.extend(_discover_from_path(path, root))
        if visited_files > config.discovery.max_files:
            break

    deduped = _dedupe(items)
    counts: dict[str, int] = {}
    for item in deduped:
        counts[item.item_type] = counts.get(item.item_type, 0) + 1

    return {
        "schema_version": "amby.framework_inventory.v1",
        "enabled": True,
        "roots": visited_roots,
        "limits": {
            "max_depth": config.discovery.max_depth,
            "max_files": config.discovery.max_files,
            "truncated": visited_files > config.discovery.max_files,
        },
        "counts": dict(sorted(counts.items())),
        "items": [_item_dict(item) for item in deduped],
    }


def _discover_from_path(path: Path, root: Path) -> list[DiscoveredInventoryItem]:
    items: list[DiscoveredInventoryItem] = []
    if path.is_dir() and (path / "SKILL.md").exists():
        items.append(_skill_item(path / "SKILL.md", root))
    if path.is_file() and path.name in MCP_FILENAMES:
        items.extend(_mcp_items(path, root))
    if path.is_file() and path.name == "plugin.json":
        items.append(_plugin_item(path, root))
    if path.is_file() and path.name == "manifest.json" and ".codex-plugin" in path.parts:
        items.append(_plugin_item(path, root))
    return items


def _skill_item(path: Path, root: Path) -> DiscoveredInventoryItem:
    text = _read_text(path)
    metadata = _frontmatter(text)
    name = str(metadata.get("name") or path.parent.name)
    description = str(metadata.get("description") or "").strip()
    return DiscoveredInventoryItem(
        item_type="skill",
        name=name,
        source=_relative(path, root),
        risk="medium",
        metadata={"description": description[:240]} if description else {},
    )


def _plugin_item(path: Path, root: Path) -> DiscoveredInventoryItem:
    payload = _read_json(path)
    if isinstance(payload, dict):
        name = str(payload.get("name") or payload.get("id") or path.parent.name)
        metadata = {
            "id": str(payload.get("id", ""))[:120],
            "version": str(payload.get("version", ""))[:80],
            "description": str(payload.get("description", ""))[:240],
        }
    else:
        name = path.parent.name
        metadata = {}
    return DiscoveredInventoryItem(
        item_type="plugin",
        name=name,
        source=_relative(path, root),
        risk="medium",
        metadata={key: value for key, value in metadata.items() if value},
    )


def _mcp_items(path: Path, root: Path) -> list[DiscoveredInventoryItem]:
    payload = _read_json(path)
    if not isinstance(payload, dict):
        return []
    servers = payload.get("mcpServers") or payload.get("servers") or {}
    if not isinstance(servers, dict):
        return []

    items: list[DiscoveredInventoryItem] = []
    for name, server in servers.items():
        metadata: dict[str, object] = {}
        if isinstance(server, dict):
            command = str(server.get("command", "")).strip()
            url = str(server.get("url", "")).strip()
            transport = str(server.get("transport", "")).strip()
            env = server.get("env") if isinstance(server.get("env"), dict) else {}
            metadata = {
                "command": Path(command).name if command else "",
                "transport": transport,
                "url_host": _url_host(url),
                "env_keys": sorted(str(key) for key in env.keys()) if isinstance(env, dict) else [],
            }
        items.append(
            DiscoveredInventoryItem(
                item_type="mcp_server",
                name=str(name),
                source=_relative(path, root),
                risk="high",
                metadata={key: value for key, value in metadata.items() if value not in ("", [], None)},
            )
        )
    return items


def _resolve_inside_root(root: Path, configured_root: str) -> Path | None:
    candidate = (root / configured_root).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _walk(scan_root: Path, *, root: Path, max_depth: int) -> list[Path]:
    output: list[Path] = []
    stack = [scan_root]
    while stack:
        current = stack.pop()
        try:
            depth = len(current.resolve().relative_to(root).parts)
        except ValueError:
            continue
        if current.is_dir() and current.name in SKIP_DIRS:
            continue
        output.append(current)
        if not current.is_dir() or depth > max_depth:
            continue
        try:
            children = sorted(current.iterdir(), key=lambda item: (not item.is_dir(), item.name))
        except OSError:
            continue
        stack.extend(reversed(children))
    return output


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end < 0:
        return {}
    metadata: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    return metadata


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")[:4096]
    except (OSError, UnicodeDecodeError):
        return ""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _url_host(url: str) -> str:
    if not url:
        return ""
    if "://" not in url:
        return url.split("/", 1)[0]
    return url.split("://", 1)[1].split("/", 1)[0]


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def _dedupe(items: list[DiscoveredInventoryItem]) -> list[DiscoveredInventoryItem]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[DiscoveredInventoryItem] = []
    for item in items:
        key = (item.item_type, item.name, item.source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return sorted(deduped, key=lambda item: (item.item_type, item.name, item.source))


def _item_dict(item: DiscoveredInventoryItem) -> dict[str, object]:
    return {
        "type": item.item_type,
        "name": item.name,
        "source": item.source,
        "owner": item.owner,
        "risk": item.risk,
        "metadata": item.metadata or {},
    }

