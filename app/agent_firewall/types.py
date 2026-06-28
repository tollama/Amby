from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCallRequest:
    request_id: str
    agent_id: str
    session_id: str | None
    tool_name: str
    action: str
    method: str
    url: str | None = None
    target_host: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    approval_id: str | None = None
    retrieval_context_ref: str | None = None
    tool_definition_ref: str | None = None


@dataclass(frozen=True)
class FirewallDecision:
    request_id: str
    decision: str
    risk_level: str
    reasons: list[str]
    detections: list[dict[str, object]]
    latency_ms: int
    target_host: str | None = None
    target: str | None = None
    approval_id: str | None = None
    inventory: dict[str, object] | None = None
    error: str | None = None

