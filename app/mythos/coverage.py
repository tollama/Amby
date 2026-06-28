from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


MYTHOS_SOURCE = {
    "title": "The AI Vulnerability Storm: Building a Mythos-ready Security Program",
    "publisher": "Cloud Security Alliance CISO Community, SANS, [un]prompted, OWASP Gen AI Security Project",
    "source_url": "https://labs.cloudsecurityalliance.org/mythos-ciso/",
    "pdf_url": "https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/mythosreadyv1.0.pdf",
    "original_release": "2026-04-12",
    "last_updated": "2026-05-01",
}


@dataclass(frozen=True)
class MythosControl:
    control_id: str
    title: str
    source_focus: str
    status: str
    roadmap_phase: str
    evidence_rule: str
    mappings: tuple[str, ...]
    current_scope: str
    next_step: str


MYTHOS_CONTROLS = (
    MythosControl(
        control_id="MYTHOS-00",
        title="Automated audit data collection and tamper-evident evidence",
        source_focus="Key takeaway: automate audit data collection and reporting.",
        status="implemented",
        roadmap_phase="Phase 0",
        evidence_rule="event_count",
        mappings=("NIST AI RMF MEASURE", "NIST AI RMF MANAGE", "ASI evidence"),
        current_scope="Audit events, config snapshot, JSONL/CSV export, hash chain, and manifest hash are generated locally.",
        next_step="Add WORM storage or external notarization before formal compliance use.",
    ),
    MythosControl(
        control_id="MYTHOS-01",
        title="LLM-driven code and pipeline security review",
        source_focus="Priority action: point agents at code and pipelines.",
        status="planned",
        roadmap_phase="Phase 2",
        evidence_rule="none",
        mappings=("LLM03", "LLM04", "ASI04", "NIST AI RMF MEASURE"),
        current_scope="Not part of the runtime gateway MVP.",
        next_step="Add CI runner evidence for code review, prompt regression, red-team results, SBOM, and AIBOM.",
    ),
    MythosControl(
        control_id="MYTHOS-02",
        title="AI agent adoption with mandatory oversight",
        source_focus="Priority action: require AI agent adoption with security controls and oversight.",
        status="implemented",
        roadmap_phase="Phase 1",
        evidence_rule="tool_oversight",
        mappings=("LLM06", "ASI02", "ASI03", "NIST AI RMF GOVERN"),
        current_scope="Tool-call policy evaluates agent identity, owner, tool scope, egress, risk, and human approval before dispatch.",
        next_step="Move approval workflow from local API records to team RBAC and signed policy bundles.",
    ),
    MythosControl(
        control_id="MYTHOS-03",
        title="Defend agent harnesses, prompts, outputs, and tools",
        source_focus="Priority action: defend your agents.",
        status="implemented",
        roadmap_phase="Phase 1.5",
        evidence_rule="active_asi",
        mappings=("LLM01", "LLM02", "LLM04", "LLM06", "LLM08", "ASI01", "ASI02", "ASI06", "ASI09"),
        current_scope="Prompt/output scanning, tool-call firewall decisions, memory hooks, and RAG context hooks are audited with OWASP/NIST/ASI tags.",
        next_step="Extend enforcement to deeper framework-specific state graphs and agent-to-agent communication hooks.",
    ),
    MythosControl(
        control_id="MYTHOS-04",
        title="Acceleration governance for defensive AI onboarding",
        source_focus="Priority action: establish innovation and acceleration governance.",
        status="planned",
        roadmap_phase="Phase 2.5",
        evidence_rule="none",
        mappings=("NIST AI RMF GOVERN", "policy bundle", "control plane"),
        current_scope="Local policy and evidence exist, but cross-functional approval workflow is not implemented.",
        next_step="Add signed policy bundles, exception review, approval records, and fleet-level policy drift detection.",
    ),
    MythosControl(
        control_id="MYTHOS-05",
        title="Continuous patching and vulnerability operations",
        source_focus="Priority action: prepare for continuous patching and stand up VulnOps.",
        status="planned",
        roadmap_phase="Phase 2",
        evidence_rule="none",
        mappings=("LLM03", "LLM04", "ASI04", "NIST AI RMF MANAGE"),
        current_scope="The MVP does not scan code dependencies, patch windows, or exploitability.",
        next_step="Create VulnOps evidence from dependency scans, patch SLAs, exploit validation, and remediation status.",
    ),
    MythosControl(
        control_id="MYTHOS-06",
        title="Updated AI-speed risk metrics and reporting",
        source_focus="Priority action: update risk models and reporting.",
        status="implemented",
        roadmap_phase="Phase 0",
        evidence_rule="event_count",
        mappings=("ASI counts", "decision counts", "latency", "NIST AI RMF MEASURE"),
        current_scope="Reports include event counts, decision counts, ASI distribution, request IDs, and hash-chain head.",
        next_step="Add time-windowed trends, severity-weighted risk score, false-positive rate, and owner-level accountability.",
    ),
    MythosControl(
        control_id="MYTHOS-07",
        title="Agent, tool, and exposure inventory",
        source_focus="Priority action: inventory and reduce attack surface.",
        status="implemented",
        roadmap_phase="Phase 1.5",
        evidence_rule="agent_exposure_inventory",
        mappings=("ASI04", "ASI10", "AIBOM", "MCP inventory"),
        current_scope="Configured tool inventory plus local MCP/plugin/skill discovery records owner, permission scope, data access, risk, allowed agents, and source paths.",
        next_step="Add dependency provenance, package signing, and managed fleet-wide inventory drift detection.",
    ),
    MythosControl(
        control_id="MYTHOS-08",
        title="Environment hardening evidence",
        source_focus="Priority action: harden your environment.",
        status="partial",
        roadmap_phase="Phase 1",
        evidence_rule="secrets_or_pii",
        mappings=("ASI03", "ASI09", "egress policy", "Zero Trust evidence"),
        current_scope="Secret and PII leakage are detected at the model boundary; network segmentation and MFA are external controls.",
        next_step="Add egress allowlists, virtual keys, scoped credentials, and integrations that attest MFA/segmentation state.",
    ),
    MythosControl(
        control_id="MYTHOS-09",
        title="Deception and honeytoken detection",
        source_focus="Priority action: build deception capability.",
        status="planned",
        roadmap_phase="Phase 3",
        evidence_rule="none",
        mappings=("ASI03", "ASI09", "exfiltration detection"),
        current_scope="No dedicated honeytoken or deception sensor exists in the MVP.",
        next_step="Add canary secrets, honeytoken scanners, and policy actions for attempted exfiltration.",
    ),
    MythosControl(
        control_id="MYTHOS-10",
        title="Automated response and containment",
        source_focus="Priority action: build automated response capability.",
        status="planned",
        roadmap_phase="Phase 3",
        evidence_rule="none",
        mappings=("ASI08", "kill switch", "containment playbook"),
        current_scope="The MVP can block individual model calls but does not trigger broader containment workflows.",
        next_step="Add circuit breakers, kill switches, SIEM/SOAR hooks, and approval-gated response playbooks.",
    ),
)


def build_mythos_readiness(stats: dict[str, Any]) -> dict[str, Any]:
    controls = []
    status_counts: dict[str, int] = {}
    evidence_counts = {"present": 0, "missing": 0}
    for control in MYTHOS_CONTROLS:
        row = asdict(control)
        row["evidence_present"] = _evidence_present(control.evidence_rule, stats)
        controls.append(row)
        status_counts[control.status] = status_counts.get(control.status, 0) + 1
        evidence_counts["present" if row["evidence_present"] else "missing"] += 1

    return {
        "schema_version": "amby.mythos_readiness.v1",
        "source": MYTHOS_SOURCE,
        "status_counts": dict(sorted(status_counts.items())),
        "evidence_counts": evidence_counts,
        "runtime_evidence": {
            "event_count": stats.get("events", 0),
            "tool_call_count": stats.get("tool_calls", 0),
            "context_event_count": stats.get("context_events", 0),
            "tool_inventory": stats.get("tool_inventory", 0),
            "discovered_inventory": stats.get("discovered_inventory", 0),
            "decisions": stats.get("decisions", {}),
            "tool_decisions": stats.get("tool_decisions", {}),
            "context_decisions": stats.get("context_decisions", {}),
            "context_hooks": stats.get("context_hooks", {}),
            "active_asi": stats.get("asi", {}),
            "scanners_run": stats.get("scanners_run", {}),
        },
        "controls": controls,
        "interpretation": (
            "Amby MVP is a Mythos-ready evidence and model-boundary control seed, not a full Mythos-ready "
            "security program. Planned controls require CI/CD, signed inventory provenance, VulnOps, "
            "and response integrations."
        ),
    }


def _evidence_present(rule: str, stats: dict[str, Any]) -> bool:
    if rule == "none":
        return False
    if rule == "event_count":
        return int(stats.get("events", 0)) > 0
    if rule == "active_asi":
        return bool(stats.get("asi"))
    if rule == "secrets_or_pii":
        asi_counts = stats.get("asi", {})
        return bool(asi_counts.get("ASI03") or asi_counts.get("ASI09"))
    if rule == "tool_oversight":
        tool_decisions = stats.get("tool_decisions", {})
        return int(stats.get("tool_calls", 0)) > 0 and bool(tool_decisions)
    if rule == "tool_inventory":
        return int(stats.get("tool_inventory", 0)) > 0
    if rule == "agent_exposure_inventory":
        return int(stats.get("tool_inventory", 0)) > 0 or int(stats.get("discovered_inventory", 0)) > 0
    return False
