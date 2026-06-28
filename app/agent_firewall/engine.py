from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from fnmatch import fnmatch
from typing import Any
from urllib.parse import urlparse

from app.agent_firewall.types import FirewallDecision, ToolCallRequest
from app.asi.mapping import mapping_for
from app.config import AgentFirewallConfig, ToolInventoryItem, VALID_HTTP_METHODS


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AgentFirewallEngine:
    def __init__(self, config: AgentFirewallConfig) -> None:
        self.config = config
        self._recent_calls: dict[str, deque[tuple[float, str]]] = defaultdict(deque)

    def evaluate(self, call: ToolCallRequest, *, human_approval_status: str | None = None) -> FirewallDecision:
        started = time.perf_counter()
        reasons: list[str] = []
        detections: list[dict[str, object]] = []
        decision = "allow"
        inventory_item = self._find_inventory(call.tool_name)
        method = _normalize_method(call.method)
        target_host = _target_host(call)
        target = _sanitized_target(call.url, target_host)
        risk_level = inventory_item.risk if inventory_item else _risk_from_method(method)

        if not self.config.enabled:
            return FirewallDecision(
                request_id=call.request_id,
                decision="allow",
                risk_level=risk_level,
                reasons=["agent_firewall_disabled"],
                detections=[],
                latency_ms=_elapsed_ms(started),
                target_host=target_host,
                target=target,
                inventory=_inventory_summary(inventory_item),
            )

        if self.config.circuit_breaker.enabled:
            breaker_reason = self._circuit_breaker_reason(call.agent_id)
            if breaker_reason:
                decision = "block"
                reasons.append(breaker_reason)
                detections.append(_detection("tool_unbounded_consumption", "block", breaker_reason, 1.0))

        if self.config.circuit_breaker.kill_switch:
            decision = "block"
            reasons.append("agent_firewall_kill_switch_enabled")
            detections.append(_detection("tool_unbounded_consumption", "block", "kill switch enabled", 1.0))

        if inventory_item is None:
            default_decision = self.config.default_decision
            decision = _stronger_firewall_decision(decision, default_decision)
            reasons.append("tool_not_registered_in_inventory")
            detections.append(_detection("tool_unmanaged", default_decision, "tool is not in inventory", 0.75))
        else:
            if inventory_item.allowed_agents and call.agent_id not in inventory_item.allowed_agents:
                decision = "block"
                reasons.append("agent_not_allowed_for_tool")
                detections.append(
                    _detection("tool_privilege_violation", "block", "agent is outside tool allowed_agents scope", 1.0)
                )

        egress_reason = self._egress_violation_reason(target_host, inventory_item)
        if egress_reason:
            decision = "block"
            reasons.append(egress_reason)
            detections.append(_detection("tool_egress_violation", "block", egress_reason, 1.0))

        if _is_high_risk_action(call.tool_name, call.action, method, self.config.high_risk_actions):
            risk_level = _max_risk(risk_level, "high")
            reasons.append("high_risk_tool_action")
            detections.append(_detection("tool_excessive_agency", "approval_required", "high-risk tool action", 0.9))

        approval_required = self._requires_approval(inventory_item, risk_level)
        if decision != "block" and approval_required:
            if human_approval_status == "approved":
                reasons.append("human_approval_verified")
                decision = "allow"
            else:
                decision = "approval_required"
                reasons.append("human_approval_required_before_dispatch")
                detections.append(
                    _detection(
                        "tool_approval_required",
                        "approval_required",
                        "human approval is required before dispatch",
                        0.9,
                    )
                )

        if not reasons:
            reasons.append("tool_call_allowed_by_policy")

        if self.config.circuit_breaker.enabled:
            self._record_recent_call(call.agent_id, decision)

        return FirewallDecision(
            request_id=call.request_id,
            decision=decision,
            risk_level=risk_level,
            reasons=_dedupe(reasons),
            detections=_dedupe_detections(detections),
            latency_ms=_elapsed_ms(started),
            target_host=target_host,
            target=target,
            approval_id=call.approval_id,
            inventory=_inventory_summary(inventory_item),
        )

    def inventory(self) -> list[dict[str, object]]:
        return [_inventory_summary(item) for item in self.config.inventory if _inventory_summary(item) is not None]

    def _find_inventory(self, tool_name: str) -> ToolInventoryItem | None:
        for item in self.config.inventory:
            if item.name == tool_name:
                return item
        for item in self.config.inventory:
            if fnmatch(tool_name, item.name):
                return item
        return None

    def _egress_violation_reason(self, target_host: str | None, inventory_item: ToolInventoryItem | None) -> str | None:
        if not target_host:
            return None
        if _matches_any(target_host, self.config.blocked_egress):
            return "target_host_blocked_by_egress_policy"
        if self.config.egress_allowlist and not _matches_any(target_host, self.config.egress_allowlist):
            return "target_host_not_in_global_egress_allowlist"
        if inventory_item and inventory_item.egress and not _matches_any(target_host, inventory_item.egress):
            return "target_host_not_in_tool_egress_scope"
        return None

    def _requires_approval(self, inventory_item: ToolInventoryItem | None, risk_level: str) -> bool:
        if inventory_item and inventory_item.approval_required:
            return True
        return risk_level in self.config.approval.required_for_risk

    def _circuit_breaker_reason(self, agent_id: str) -> str | None:
        now = time.monotonic()
        calls = self._recent_calls[agent_id]
        while calls and now - calls[0][0] > 60:
            calls.popleft()
        if len(calls) >= self.config.circuit_breaker.max_tool_calls_per_minute:
            return "tool_call_rate_limit_exceeded"
        blocked_count = sum(1 for _, decision in calls if decision == "block")
        if blocked_count >= self.config.circuit_breaker.max_blocked_calls_per_minute:
            return "blocked_tool_call_rate_limit_exceeded"
        return None

    def _record_recent_call(self, agent_id: str, decision: str) -> None:
        self._recent_calls[agent_id].append((time.monotonic(), decision))


def payload_fingerprint(arguments: dict[str, Any]) -> str:
    keys = sorted(str(key) for key in arguments)
    joined = ",".join(keys)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _detection(control: str, action: str, reason: str, score: float) -> dict[str, object]:
    asi = mapping_for(control)
    return {
        "scanner": control,
        "control": control,
        "asi_id": asi.asi_id,
        "llm_id": asi.llm_id,
        "owasp_llm": list(asi.owasp_llm),
        "owasp_asi": list(asi.owasp_asi),
        "nist_rmf": list(asi.nist_rmf),
        "nist_genai": list(asi.nist_genai),
        "severity": asi.severity,
        "score": score,
        "action": action,
        "label": asi.label,
        "reason": reason,
        "snippet_masked": reason,
    }


def _target_host(call: ToolCallRequest) -> str | None:
    if call.target_host:
        return call.target_host.lower()
    if not call.url:
        return None
    parsed = urlparse(call.url)
    return parsed.hostname.lower() if parsed.hostname else None


def _sanitized_target(url: str | None, target_host: str | None) -> str | None:
    if not url:
        return target_host
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return target_host or url.split("?", 1)[0]
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _normalize_method(method: str) -> str:
    normalized = (method or "POST").upper()
    if normalized not in VALID_HTTP_METHODS:
        return "POST"
    return normalized


def _risk_from_method(method: str) -> str:
    return "medium" if method in MUTATING_METHODS else "low"


def _is_high_risk_action(tool_name: str, action: str, method: str, patterns: tuple[str, ...]) -> bool:
    value_candidates = [tool_name, action, f"{tool_name}.{action}"]
    if method in MUTATING_METHODS and any(keyword in action for keyword in ("create", "update", "delete", "send", "transfer")):
        return True
    return any(fnmatch(candidate, pattern) for candidate in value_candidates for pattern in patterns)


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    normalized = value.lower()
    return any(fnmatch(normalized, pattern.lower()) for pattern in patterns)


def _max_risk(left: str, right: str) -> str:
    return left if RISK_ORDER[left] >= RISK_ORDER[right] else right


def _stronger_firewall_decision(left: str, right: str) -> str:
    order = {"allow": 0, "approval_required": 1, "block": 2}
    return left if order[left] >= order[right] else right


def _inventory_summary(item: ToolInventoryItem | None) -> dict[str, object] | None:
    if item is None:
        return None
    return {
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


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _dedupe_detections(detections: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[object, object, object]] = set()
    output: list[dict[str, object]] = []
    for detection in detections:
        key = (detection.get("control"), detection.get("action"), detection.get("reason"))
        if key in seen:
            continue
        seen.add(key)
        output.append(detection)
    return output


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)

