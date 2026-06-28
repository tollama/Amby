from __future__ import annotations

import hashlib
import os
import subprocess
import time
from pathlib import Path
from typing import Callable

from app.audit.sanitize import sanitize_audit_snippet
from app.config import PredeployAdapterConfig
from app.predeploy.normalizers import (
    adapter_error_finding,
    normalize_garak_output,
    normalize_promptfoo_output,
    normalize_pyrit_output,
    pass_finding,
)
from app.predeploy.types import AdapterRunResult, CommandResult, PredeployFinding


Normalizer = Callable[[str, str], list[PredeployFinding]]


NORMALIZERS: dict[str, Normalizer] = {
    "garak": normalize_garak_output,
    "pyrit": normalize_pyrit_output,
    "promptfoo": normalize_promptfoo_output,
}


FIXTURE_FINDINGS: dict[str, tuple[PredeployFinding, ...]] = {
    "garak": (
        pass_finding(
            adapter="garak",
            control="prompt_injection",
            evidence="Fixture garak check passed for prompt injection probes.",
        ),
        pass_finding(
            adapter="garak",
            control="leakage",
            evidence="Fixture garak check passed for leakage probes.",
        ),
    ),
    "pyrit": (
        pass_finding(
            adapter="pyrit",
            control="unsafe_tool_use",
            evidence="Fixture PyRIT check passed for unsafe tool-use objectives.",
        ),
        pass_finding(
            adapter="pyrit",
            control="rag_poisoning",
            evidence="Fixture PyRIT check passed for RAG poisoning objectives.",
        ),
    ),
    "promptfoo": (
        pass_finding(
            adapter="promptfoo",
            control="prompt_injection",
            evidence="Fixture Promptfoo regression passed for prompt injection test cases.",
            target="promptfooconfig.yaml",
        ),
        pass_finding(
            adapter="promptfoo",
            control="leakage",
            evidence="Fixture Promptfoo regression passed for leakage test cases.",
            target="promptfooconfig.yaml",
        ),
    ),
}


class CommandExecutor:
    def run(self, command: tuple[str, ...], *, cwd: Path, timeout_seconds: int) -> CommandResult:
        start = time.perf_counter()
        env = _command_env(cwd)
        try:
            completed = subprocess.run(
                list(command),
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env=env,
            )
            duration_ms = int((time.perf_counter() - start) * 1000)
            return CommandResult(
                command=command,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                duration_ms=duration_ms,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return CommandResult(
                command=command,
                exit_code=124,
                stdout=_bytes_or_text(exc.stdout),
                stderr=_bytes_or_text(exc.stderr),
                duration_ms=duration_ms,
                timed_out=True,
                error=f"Command timed out after {timeout_seconds} seconds.",
            )
        except OSError as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return CommandResult(
                command=command,
                exit_code=127,
                stdout="",
                stderr=str(exc),
                duration_ms=duration_ms,
                error=str(exc),
            )


class PredeployAdapterRunner:
    def __init__(self, *, executor: CommandExecutor | None = None, workspace_root: Path | None = None) -> None:
        self.executor = executor or CommandExecutor()
        self.workspace_root = workspace_root or Path.cwd()

    def run_adapter(
        self,
        name: str,
        config: PredeployAdapterConfig,
        *,
        use_fixtures: bool = False,
    ) -> AdapterRunResult:
        if not config.enabled:
            return AdapterRunResult(adapter=name, status="disabled", findings=())
        if use_fixtures:
            findings = FIXTURE_FINDINGS.get(name, ())
            return AdapterRunResult(adapter=name, status="pass", findings=findings)
        command = tuple([*config.command, *config.args])
        if not command:
            finding = adapter_error_finding(adapter=name, evidence=f"{name} adapter has no command configured.")
            return AdapterRunResult(adapter=name, status="error", findings=(finding,), error=finding.evidence)

        output_file = _extract_output_file(command, self.workspace_root)
        if output_file is not None and output_file.exists():
            output_file.unlink()
        if output_file is not None:
            output_file.parent.mkdir(parents=True, exist_ok=True)
        command_result = self.executor.run(command, cwd=self.workspace_root, timeout_seconds=config.timeout_seconds)
        command_result = _with_output_file(command_result, output_file)
        normalizer = NORMALIZERS.get(name)
        findings = normalizer(command_result.stdout, command_result.stderr) if normalizer else []
        if command_result.exit_code != 0:
            scanner_reported_failure = any(finding.decision in {"fail", "warn"} for finding in findings)
            if not scanner_reported_failure:
                evidence = command_result.error or _first_nonempty_line(command_result.stderr, command_result.stdout) or f"{name} command exited {command_result.exit_code}."
                findings.append(adapter_error_finding(adapter=name, evidence=evidence))
        elif not findings:
            findings.append(pass_finding(adapter=name, control="prompt_injection", evidence=f"{name} command completed without parsed findings."))

        status = _adapter_status(findings)
        error = None
        if status == "error":
            error = next((finding.evidence for finding in findings if finding.decision == "error"), None)
        return AdapterRunResult(
            adapter=name,
            status=status,
            findings=tuple(findings),
            command_result=command_result,
            error=error,
        )


def sanitized_command_summary(result: CommandResult | None) -> dict[str, object]:
    if result is None:
        return {}
    return {
        "command": _sanitize_command(result.command),
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "timed_out": result.timed_out,
        "stdout_sha256": hashlib.sha256(result.stdout.encode("utf-8", errors="replace")).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr.encode("utf-8", errors="replace")).hexdigest(),
        "stdout_bytes": len(result.stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(result.stderr.encode("utf-8", errors="replace")),
        "error": sanitize_audit_snippet(result.error or "")[:300] or None,
        "stderr_summary": sanitize_audit_snippet(_first_nonempty_line(result.stderr) or "")[:300] or None,
    }


def _extract_output_file(command: tuple[str, ...], cwd: Path) -> Path | None:
    for index, part in enumerate(command):
        if part not in {"--output", "-o"} or index + 1 >= len(command):
            continue
        candidate = command[index + 1]
        if candidate.startswith("-"):
            continue
        path = Path(candidate)
        return path if path.is_absolute() else cwd / path
    return None


def _with_output_file(result: CommandResult, output_file: Path | None) -> CommandResult:
    if output_file is None or not output_file.exists() or not output_file.is_file():
        return result
    output_text = output_file.read_text(encoding="utf-8", errors="replace")
    return CommandResult(
        command=result.command,
        exit_code=result.exit_code,
        stdout=output_text,
        stderr=result.stderr,
        duration_ms=result.duration_ms,
        timed_out=result.timed_out,
        error=result.error,
    )


def _command_env(cwd: Path) -> dict[str, str]:
    env = os.environ.copy()
    predeploy_home = cwd / ".amby-predeploy"
    promptfoo_dir = predeploy_home / "promptfoo"
    promptfoo_dir.mkdir(parents=True, exist_ok=True)
    env.setdefault("PROMPTFOO_CONFIG_DIR", str(promptfoo_dir))
    env.setdefault("PROMPTFOO_CACHE_PATH", str(promptfoo_dir / "cache"))
    env.setdefault("PROMPTFOO_DISABLE_TELEMETRY", "1")
    return env


def _adapter_status(findings: list[PredeployFinding]) -> str:
    decisions = {finding.decision for finding in findings}
    if "error" in decisions:
        return "error"
    if "fail" in decisions:
        return "fail"
    if "warn" in decisions:
        return "warn"
    return "pass"


def _sanitize_command(command: tuple[str, ...]) -> list[str]:
    sanitized: list[str] = []
    redact_next = False
    for part in command:
        lowered = part.lower()
        if redact_next:
            sanitized.append("[REDACTED_SECRET]")
            redact_next = False
            continue
        if lowered in {"--api-key", "--token", "--password", "--secret"}:
            sanitized.append(part)
            redact_next = True
            continue
        sanitized.append(sanitize_audit_snippet(part))
    return sanitized


def _first_nonempty_line(*texts: str) -> str | None:
    for text in texts:
        for line in text.splitlines():
            if line.strip():
                return line.strip()
    return None


def _bytes_or_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
