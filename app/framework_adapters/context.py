from __future__ import annotations

from app.asi.mapping import mapping_for
from app.config import ContextHookConfig, FrameworkAdaptersConfig
from app.framework_adapters.types import AdapterSpec, ContextHookDecision, ContextHookRequest
from app.guardrails.engine import GuardrailEngine


ADAPTER_SPECS: tuple[AdapterSpec, ...] = (
    AdapterSpec(
        name="langgraph",
        status="implemented",
        hooks=("tool_call", "memory_write", "retrieval_context"),
        package_hint="LangGraph tool node / checkpointer / retriever wrapper",
        integration_note="Call Amby before ToolNode dispatch, before memory checkpoint writes, and before retrieved context is appended to state.",
    ),
    AdapterSpec(
        name="crewai",
        status="implemented",
        hooks=("tool_call", "memory_write", "retrieval_context"),
        package_hint="CrewAI tool / memory / knowledge source wrapper",
        integration_note="Call Amby before BaseTool execution, memory persistence, and knowledge-source context injection.",
    ),
    AdapterSpec(
        name="llamaindex",
        status="implemented",
        hooks=("tool_call", "memory_write", "retrieval_context"),
        package_hint="LlamaIndex tool / memory / retriever postprocessor wrapper",
        integration_note="Call Amby before tool execution, chat memory writes, and retriever result handoff to the synthesizer.",
    ),
)


class ContextHookEngine:
    def __init__(self, config: FrameworkAdaptersConfig, guardrails: GuardrailEngine) -> None:
        self.config = config
        self.guardrails = guardrails

    def evaluate(self, request: ContextHookRequest) -> ContextHookDecision:
        hook_config = self.config.context_hooks.get(request.hook_type, ContextHookConfig())
        if not self.config.enabled or not hook_config.enabled:
            return ContextHookDecision(
                request_id=request.request_id,
                framework=request.framework,
                hook_type=request.hook_type,
                agent_id=request.agent_id,
                decision="allow",
                texts=request.texts,
                scanners_run=[],
                detections=[],
                latency_ms=0,
                source_ref=request.source_ref,
                error="context hook disabled",
            )

        decision = self.guardrails.scan_texts(
            request.texts,
            direction=hook_config.source_direction,
            model=f"{request.framework}:{request.hook_type}",
            request_id=request.request_id,
        )
        detections = list(decision.detections)
        if hook_config.add_context_mapping and detections:
            detections.append(_context_detection(request.hook_type, decision.decision))

        return ContextHookDecision(
            request_id=request.request_id,
            framework=request.framework,
            hook_type=request.hook_type,
            agent_id=request.agent_id,
            decision=decision.decision,
            texts=decision.texts,
            scanners_run=decision.scanners_run,
            detections=detections,
            latency_ms=decision.latency_ms,
            source_ref=request.source_ref,
            error=decision.error,
        )


def adapter_specs(config: FrameworkAdaptersConfig) -> list[dict[str, object]]:
    enabled = set(config.adapters)
    rows: list[dict[str, object]] = []
    for spec in ADAPTER_SPECS:
        rows.append(
            {
                "name": spec.name,
                "enabled": spec.name in enabled,
                "status": spec.status if spec.name in enabled else "disabled",
                "hooks": list(spec.hooks),
                "package_hint": spec.package_hint,
                "integration_note": spec.integration_note,
            }
        )
    return rows


def _context_detection(hook_type: str, action: str) -> dict[str, object]:
    control = "rag_context_risk" if hook_type == "retrieval_context" else "memory_poisoning"
    asi = mapping_for(control)
    reason = "retrieval context produced risky model input" if hook_type == "retrieval_context" else "memory write contains risky context"
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
        "score": 0.9,
        "action": action,
        "label": asi.label,
        "reason": reason,
        "snippet_masked": reason,
    }
