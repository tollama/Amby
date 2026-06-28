from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogItem:
    item_type: str
    name: str
    ecosystem: str
    source: str
    risk: str
    install_state: str
    metadata: dict[str, object]


BUILTIN_CATALOG_ITEMS: tuple[CatalogItem, ...] = (
    CatalogItem(
        item_type="mcp_server",
        name="filesystem",
        ecosystem="modelcontextprotocol",
        source="builtin:mcp-reference",
        risk="high",
        install_state="available",
        metadata={
            "package": "@modelcontextprotocol/server-filesystem",
            "capabilities": ["local_file_read", "local_file_write"],
            "recommended_controls": ["path_allowlist", "read_only_default", "human_approval_for_write_delete"],
            "reference_url": "https://github.com/modelcontextprotocol/servers",
        },
    ),
    CatalogItem(
        item_type="mcp_server",
        name="fetch",
        ecosystem="modelcontextprotocol",
        source="builtin:mcp-reference",
        risk="medium",
        install_state="available",
        metadata={
            "package": "@modelcontextprotocol/server-fetch",
            "capabilities": ["web_fetch"],
            "recommended_controls": ["egress_allowlist", "domain_blocklist", "response_size_limit"],
            "reference_url": "https://github.com/modelcontextprotocol/servers",
        },
    ),
    CatalogItem(
        item_type="mcp_server",
        name="git",
        ecosystem="modelcontextprotocol",
        source="builtin:mcp-reference",
        risk="high",
        install_state="available",
        metadata={
            "package": "@modelcontextprotocol/server-git",
            "capabilities": ["repo_read", "repo_write"],
            "recommended_controls": ["workspace_allowlist", "diff_review", "human_approval_for_write"],
            "reference_url": "https://github.com/modelcontextprotocol/servers",
        },
    ),
    CatalogItem(
        item_type="mcp_server",
        name="memory",
        ecosystem="modelcontextprotocol",
        source="builtin:mcp-reference",
        risk="high",
        install_state="available",
        metadata={
            "package": "@modelcontextprotocol/server-memory",
            "capabilities": ["persistent_memory"],
            "recommended_controls": ["memory_write_hook", "retention_policy", "poisoning_scan"],
            "reference_url": "https://github.com/modelcontextprotocol/servers",
        },
    ),
    CatalogItem(
        item_type="mcp_server",
        name="sequentialthinking",
        ecosystem="modelcontextprotocol",
        source="builtin:mcp-reference",
        risk="medium",
        install_state="available",
        metadata={
            "package": "@modelcontextprotocol/server-sequential-thinking",
            "capabilities": ["reasoning_state"],
            "recommended_controls": ["state_size_limit", "prompt_injection_scan", "audit_reasoning_boundaries"],
            "reference_url": "https://github.com/modelcontextprotocol/servers",
        },
    ),
    CatalogItem(
        item_type="agent_skill",
        name="build-mcp-server",
        ecosystem="agent-skills",
        source="builtin:mcp-skills",
        risk="high",
        install_state="available",
        metadata={
            "capabilities": ["scaffold_mcp_server", "generate_server_code"],
            "recommended_controls": ["code_review", "sandbox_tests", "dependency_review"],
            "reference_url": "https://modelcontextprotocol.io/docs/develop/build-agent-skills",
        },
    ),
    CatalogItem(
        item_type="agent_skill",
        name="build-mcp-app",
        ecosystem="agent-skills",
        source="builtin:mcp-skills",
        risk="high",
        install_state="available",
        metadata={
            "capabilities": ["scaffold_mcp_app", "generate_client_code"],
            "recommended_controls": ["code_review", "network_policy_review", "secret_scan"],
            "reference_url": "https://modelcontextprotocol.io/docs/develop/build-agent-skills",
        },
    ),
    CatalogItem(
        item_type="agent_skill",
        name="build-mcpb",
        ecosystem="agent-skills",
        source="builtin:mcp-skills",
        risk="medium",
        install_state="available",
        metadata={
            "capabilities": ["package_mcp_bundle"],
            "recommended_controls": ["manifest_review", "signature_verification", "dependency_review"],
            "reference_url": "https://modelcontextprotocol.io/docs/develop/build-agent-skills",
        },
    ),
)


def builtin_catalog_items() -> list[dict[str, object]]:
    return [
        {
            "type": item.item_type,
            "name": item.name,
            "ecosystem": item.ecosystem,
            "source": item.source,
            "risk": item.risk,
            "install_state": item.install_state,
            "metadata": item.metadata,
        }
        for item in BUILTIN_CATALOG_ITEMS
    ]

