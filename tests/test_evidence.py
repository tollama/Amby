import json
from pathlib import Path

from app.audit.store import AuditEventInput, AuditStore, ContextEventInput, ToolCallEventInput
from app.evidence.generator import EvidenceOptions, generate_evidence_package, verify_evidence_package


def test_evidence_package_generation_and_verification(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text("audit:\n  store: audit.db\n", encoding="utf-8")

    store = AuditStore(str(db_path))
    store.initialize()
    store.record_event(
        AuditEventInput(
            request_id="req-evidence",
            direction="output",
            upstream_model="gpt-test",
            scanners_run=["pii"],
            detections=[
                {
                    "scanner": "pii",
                    "asi_id": "ASI09",
                    "severity": "medium",
                    "score": 0.95,
                    "action": "redact",
                    "snippet_masked": "Contact [REDACTED_EMAIL].",
                }
            ],
            decision="redact",
            latency_ms=2,
            error=None,
            client_meta={"ip_hash": "abc"},
        )
    )
    store.record_tool_call_event(
        ToolCallEventInput(
            request_id="req-tool-evidence",
            agent_id="finance-assistant",
            session_id="session-1",
            tool_name="stripe.create_payment",
            action="create_payment",
            method="POST",
            target_host="api.stripe.com",
            target="https://api.stripe.com/v1/payment_intents",
            decision="approval_required",
            risk_level="high",
            approval_id="approval-1",
            latency_ms=1,
            detections=[
                {
                    "scanner": "tool_approval_required",
                    "control": "tool_approval_required",
                    "asi_id": "ASI02",
                    "llm_id": "LLM06",
                    "owasp_llm": ["LLM06"],
                    "owasp_asi": ["ASI02"],
                    "nist_rmf": ["GOVERN", "MANAGE"],
                    "nist_genai": ["human-ai-configuration"],
                    "severity": "medium",
                    "score": 0.9,
                    "action": "approval_required",
                    "snippet_masked": "human approval is required before dispatch",
                }
            ],
            reasons=["human_approval_required_before_dispatch"],
            policy_snapshot={"approval_status": "pending", "argument_keys": ["amount"]},
            client_meta={},
        )
    )
    store.record_context_event(
        ContextEventInput(
            request_id="req-context-evidence",
            framework="langgraph",
            hook_type="memory_write",
            agent_id="support-assistant",
            session_id="session-1",
            source_ref="thread:memory",
            decision="block",
            latency_ms=1,
            scanners_run=["prompt_injection"],
            detections=[
                {
                    "scanner": "memory_poisoning",
                    "control": "memory_poisoning",
                    "asi_id": "ASI06",
                    "llm_id": "LLM04",
                    "owasp_llm": ["LLM04"],
                    "owasp_asi": ["ASI06"],
                    "nist_rmf": ["MAP", "MEASURE", "MANAGE"],
                    "nist_genai": ["information-integrity"],
                    "severity": "high",
                    "score": 0.9,
                    "action": "block",
                    "snippet_masked": "memory write contains risky context",
                }
            ],
            policy_snapshot={"hook_type": "memory_write", "text_count": 1},
            client_meta={},
            error=None,
        )
    )

    manifest = generate_evidence_package(
        EvidenceOptions(
            db_path=str(db_path),
            config_path=str(config_path),
            output_root=str(tmp_path / "evidence"),
            generated_at="2026-06-27T000000Z",
            package_name="proof",
        )
    )
    package_dir = Path(manifest["package_dir"])

    assert (package_dir / "report.md").exists()
    assert (package_dir / "manifest.json").exists()
    assert (package_dir / "audit_events.jsonl").exists()
    assert (package_dir / "tool_call_events.jsonl").exists()
    assert (package_dir / "tool_call_chain.jsonl").exists()
    assert (package_dir / "context_events.jsonl").exists()
    assert (package_dir / "context_chain.jsonl").exists()
    assert (package_dir / "discovered_inventory.json").exists()
    assert (package_dir / "mythos_ready.json").exists()
    assert "Tool-call Decision Counts" in (package_dir / "report.md").read_text(encoding="utf-8")
    assert "Context Hook Decision Counts" in (package_dir / "report.md").read_text(encoding="utf-8")
    assert "ASI09" in (package_dir / "report.md").read_text(encoding="utf-8")
    assert "Mythos-ready Coverage" in (package_dir / "report.md").read_text(encoding="utf-8")

    mythos = json.loads((package_dir / "mythos_ready.json").read_text(encoding="utf-8"))
    inventory = json.loads((package_dir / "discovered_inventory.json").read_text(encoding="utf-8"))
    assert mythos["schema_version"] == "amby.mythos_readiness.v1"
    assert mythos["status_counts"]["implemented"] >= 5
    assert mythos["runtime_evidence"]["active_asi"] == {"ASI02": 1, "ASI06": 1, "ASI09": 1}
    assert mythos["runtime_evidence"]["tool_call_count"] == 1
    assert mythos["runtime_evidence"]["context_event_count"] == 1
    assert mythos["runtime_evidence"]["catalog_inventory"] > 0
    assert any(item["name"] == "filesystem" for item in inventory["catalog"]["items"])
    assert any(
        control["control_id"] == "MYTHOS-00" and control["evidence_present"]
        for control in mythos["controls"]
    )
    assert manifest["mythos_readiness"]["status_counts"]["planned"] >= 1

    verification = verify_evidence_package(package_dir)
    assert verification["valid"] is True
    assert verification["context_chain"]["valid"] is True
