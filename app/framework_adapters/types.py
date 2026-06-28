from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ContextHookRequest:
    request_id: str
    framework: str
    hook_type: str
    agent_id: str
    session_id: str | None
    texts: list[str]
    source_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ContextHookDecision:
    request_id: str
    framework: str
    hook_type: str
    agent_id: str
    decision: str
    texts: list[str]
    scanners_run: list[str]
    detections: list[dict[str, object]]
    latency_ms: int
    source_ref: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    status: str
    hooks: tuple[str, ...]
    package_hint: str
    integration_note: str

