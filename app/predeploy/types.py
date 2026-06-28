from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


PREDEPLOY_DECISIONS = {"pass", "fail", "warn", "error"}


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error: str | None = None


@dataclass(frozen=True)
class PredeployFinding:
    adapter: str
    finding_type: str
    target: str
    severity: str
    decision: str
    control: str
    evidence: str
    asi_id: str | None = None
    llm_id: str | None = None
    owasp_llm: tuple[str, ...] = ()
    owasp_asi: tuple[str, ...] = ()
    nist_rmf: tuple[str, ...] = ()
    nist_genai: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.decision not in PREDEPLOY_DECISIONS:
            raise ValueError(f"Invalid predeploy finding decision={self.decision!r}")


@dataclass(frozen=True)
class AdapterRunResult:
    adapter: str
    status: str
    findings: tuple[PredeployFinding, ...]
    command_result: CommandResult | None = None
    error: str | None = None


@dataclass(frozen=True)
class PredeployRunResult:
    run_id: str
    suite: str
    decision: str
    adapter_status: dict[str, str]
    finding_counts: dict[str, int]
    findings: tuple[PredeployFinding, ...]
    aibom: dict[str, Any]
    output_dir: str
    duration_ms: int
    error: str | None = None

