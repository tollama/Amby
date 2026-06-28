from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.audit.store import AuditStore, PredeployFindingInput, PredeployRunInput
from app.config import AppConfig
from app.predeploy.adapters import PredeployAdapterRunner, sanitized_command_summary
from app.predeploy.aibom import aibom_component_count, generate_aibom
from app.predeploy.normalizers import aibom_supply_chain_finding
from app.predeploy.types import AdapterRunResult, PredeployFinding, PredeployRunResult


class PredeployRunner:
    def __init__(
        self,
        config: AppConfig,
        *,
        audit_store: AuditStore | None = None,
        adapter_runner: PredeployAdapterRunner | None = None,
        workspace_root: Path | None = None,
    ) -> None:
        self.config = config
        self.audit_store = audit_store or AuditStore(config.audit.store)
        self.adapter_runner = adapter_runner or PredeployAdapterRunner(workspace_root=workspace_root)
        self.workspace_root = workspace_root or Path.cwd()

    def run(
        self,
        *,
        suite: str | None = None,
        output_root: str | Path | None = None,
        use_fixtures: bool = False,
    ) -> PredeployRunResult:
        self.audit_store.initialize()
        run_id = _run_id()
        run_suite = suite or self.config.predeploy.suite
        start = time.perf_counter()
        output_dir = _create_output_dir(Path(output_root or self.config.predeploy.output_root), run_id)
        (output_dir / "tool_outputs").mkdir(parents=True, exist_ok=True)

        aibom = generate_aibom(self.config, workspace_root=self.workspace_root)
        adapter_results: list[AdapterRunResult] = []
        findings: list[PredeployFinding] = []
        adapter_status: dict[str, str] = {}

        if not self.config.predeploy.enabled:
            adapter_status["predeploy"] = "disabled"
        else:
            for name, adapter_config in sorted(self.config.predeploy.adapters.items()):
                result = self.adapter_runner.run_adapter(name, adapter_config, use_fixtures=use_fixtures)
                adapter_results.append(result)
                adapter_status[name] = result.status
                findings.extend(result.findings)
                _write_tool_output_summary(output_dir / "tool_outputs" / f"{name}.json", result)

        aibom_finding = aibom_supply_chain_finding(component_count=aibom_component_count(aibom))
        findings.append(aibom_finding)
        adapter_status["aibom"] = "pass"

        finding_counts = _finding_counts(findings)
        decision = _run_decision(finding_counts, adapter_status, self.config)
        duration_ms = int((time.perf_counter() - start) * 1000)
        error = _run_error(decision, finding_counts, adapter_status)
        summary = {
            "schema_version": "amby.predeploy.summary.v1",
            "finding_counts": finding_counts,
            "adapter_status": adapter_status,
            "aibom_counts": aibom.get("counts", {}),
            "ci_gate": self.config.predeploy.ci_gate,
        }

        result = PredeployRunResult(
            run_id=run_id,
            suite=run_suite,
            decision=decision,
            adapter_status=adapter_status,
            finding_counts=finding_counts,
            findings=tuple(findings),
            aibom=aibom,
            output_dir=str(output_dir),
            duration_ms=duration_ms,
            error=error,
        )

        self.audit_store.record_predeploy_run(
            PredeployRunInput(
                run_id=run_id,
                suite=run_suite,
                decision=decision,
                adapters={name: _adapter_config_summary(adapter) for name, adapter in sorted(self.config.predeploy.adapters.items())},
                targets=dict(self.config.predeploy.targets),
                thresholds=asdict(self.config.predeploy.thresholds),
                summary=summary,
                duration_ms=duration_ms,
                output_dir=str(output_dir),
                error=error,
            )
        )
        for finding in findings:
            self.audit_store.record_predeploy_finding(_finding_input(run_id, finding))

        _write_json(output_dir / "run.json", _run_payload(result))
        _write_json(output_dir / "summary.json", summary)
        _write_json(output_dir / "aibom.json", aibom)
        _write_jsonl(output_dir / "findings.jsonl", [_finding_payload(finding) for finding in findings])
        return result


def should_fail_ci(result: PredeployRunResult, config: AppConfig) -> bool:
    return bool(config.predeploy.ci_gate and result.decision in {"fail", "error"})


def _run_payload(result: PredeployRunResult) -> dict[str, Any]:
    return {
        "schema_version": "amby.predeploy.run.v1",
        "id": result.run_id,
        "suite": result.suite,
        "decision": result.decision,
        "adapter_status": result.adapter_status,
        "finding_counts": result.finding_counts,
        "aibom_counts": result.aibom.get("counts", {}),
        "output_dir": result.output_dir,
        "duration_ms": result.duration_ms,
        "error": result.error,
    }


def _finding_input(run_id: str, finding: PredeployFinding) -> PredeployFindingInput:
    return PredeployFindingInput(
        run_id=run_id,
        adapter=finding.adapter,
        finding_type=finding.finding_type,
        target=finding.target,
        severity=finding.severity,
        decision=finding.decision,
        control=finding.control,
        asi_id=finding.asi_id,
        llm_id=finding.llm_id,
        owasp_llm=list(finding.owasp_llm),
        owasp_asi=list(finding.owasp_asi),
        nist_rmf=list(finding.nist_rmf),
        nist_genai=list(finding.nist_genai),
        evidence=finding.evidence,
        metadata=finding.metadata,
    )


def _finding_payload(finding: PredeployFinding) -> dict[str, Any]:
    return {
        "adapter": finding.adapter,
        "finding_type": finding.finding_type,
        "target": finding.target,
        "severity": finding.severity,
        "decision": finding.decision,
        "control": finding.control,
        "asi_id": finding.asi_id,
        "llm_id": finding.llm_id,
        "owasp_llm": list(finding.owasp_llm),
        "owasp_asi": list(finding.owasp_asi),
        "nist_rmf": list(finding.nist_rmf),
        "nist_genai": list(finding.nist_genai),
        "evidence": finding.evidence,
        "metadata": finding.metadata,
    }


def _finding_counts(findings: list[PredeployFinding]) -> dict[str, int]:
    counts = {"pass": 0, "fail": 0, "warn": 0, "error": 0}
    for finding in findings:
        counts[finding.decision] = counts.get(finding.decision, 0) + 1
    return counts


def _run_decision(finding_counts: dict[str, int], adapter_status: dict[str, str], config: AppConfig) -> str:
    thresholds = config.predeploy.thresholds
    adapter_has_error = any(status == "error" for status in adapter_status.values())
    if finding_counts.get("error", 0) > thresholds.max_error_findings:
        return "error"
    if thresholds.fail_on_adapter_error and adapter_has_error:
        return "error"
    if finding_counts.get("fail", 0) > thresholds.max_fail_findings:
        return "fail"
    if finding_counts.get("warn", 0) > 0:
        return "fail" if finding_counts["warn"] > thresholds.max_warn_findings else "warn"
    return "pass"


def _run_error(decision: str, finding_counts: dict[str, int], adapter_status: dict[str, str]) -> str | None:
    if decision not in {"fail", "error"}:
        return None
    return (
        f"predeploy decision={decision}; findings={finding_counts}; "
        f"adapters={adapter_status}"
    )


def _adapter_config_summary(adapter: Any) -> dict[str, Any]:
    return {
        "enabled": bool(adapter.enabled),
        "command_name": adapter.command[0] if adapter.command else None,
        "arg_count": len(adapter.args),
        "timeout_seconds": adapter.timeout_seconds,
        "output_format": adapter.output_format,
    }


def _write_tool_output_summary(path: Path, result: AdapterRunResult) -> None:
    payload = {
        "schema_version": "amby.predeploy.tool_output_summary.v1",
        "adapter": result.adapter,
        "status": result.status,
        "finding_count": len(result.findings),
        "finding_decisions": _finding_counts(list(result.findings)),
        "command": sanitized_command_summary(result.command_result),
        "error": result.error,
    }
    _write_json(path, payload)


def _create_output_dir(root: Path, run_id: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    candidate = root / run_id
    if not candidate.exists():
        candidate.mkdir()
        return candidate
    for index in range(1, 1000):
        candidate = root / f"{run_id}-{index:03d}"
        if not candidate.exists():
            candidate.mkdir()
            return candidate
    raise FileExistsError(f"Could not create a unique predeploy output directory under {root}")


def _run_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"predeploy-{timestamp}-{uuid.uuid4().hex[:8]}"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")

