from __future__ import annotations

from app.config import PolicyConfig, ScannerRule
from app.guardrails.scanners import (
    ImproperOutputScanner,
    LlmGuardPromptInjectionScanner,
    LlmGuardSecretsScanner,
    PresidioPiiScanner,
    PromptInjectionScanner,
    RegexPiiScanner,
    SecretsScanner,
    SystemPromptLeakageScanner,
)
from app.guardrails.types import ScanContext, ScanResult, Scanner


DEFAULT_SCANNER_NAMES = ("prompt_injection", "pii", "secrets", "system_prompt_leakage", "improper_output")


class CascadingScanner:
    def __init__(self, name: str, scanners: list[Scanner]) -> None:
        self.name = name
        self._scanners = scanners

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        best = ScanResult(scanner=self.name, detected=False, score=0.0, spans=[])
        for scanner in self._scanners:
            result = scanner.scan(text, ctx)
            if result.score > best.score:
                best = ScanResult(scanner=self.name, detected=result.detected, score=result.score, spans=result.spans)
            if result.detected:
                return ScanResult(scanner=self.name, detected=True, score=result.score, spans=result.spans)
        return best


def build_default_registry(policy: PolicyConfig | None = None, use_presidio: bool = True) -> dict[str, Scanner]:
    scanner_names = set(DEFAULT_SCANNER_NAMES)
    if policy is not None:
        scanner_names.update(policy.input)
        scanner_names.update(policy.output)
    return {
        name: _build_scanner(name, _rule_for(policy, name), use_presidio=use_presidio)
        for name in sorted(scanner_names)
        if _can_build_scanner(name)
    }


def _rule_for(policy: PolicyConfig | None, scanner_name: str) -> ScannerRule:
    if policy is None:
        return ScannerRule()
    return policy.input.get(scanner_name) or policy.output.get(scanner_name) or ScannerRule()


def _can_build_scanner(scanner_name: str) -> bool:
    return scanner_name in DEFAULT_SCANNER_NAMES


def _build_scanner(scanner_name: str, rule: ScannerRule, *, use_presidio: bool) -> Scanner:
    engines = rule.cascade or _default_cascade(scanner_name, rule.engine, use_presidio=use_presidio)
    scanners: list[Scanner] = []
    for engine in engines:
        scanner = _scanner_for_engine(scanner_name, engine, use_presidio=use_presidio)
        if scanner is not None:
            scanners.append(scanner)
    if not scanners:
        scanners.append(_fallback_scanner(scanner_name))
    if len(scanners) == 1:
        return scanners[0]
    return CascadingScanner(scanner_name, scanners)


def _default_cascade(scanner_name: str, engine: str, *, use_presidio: bool) -> tuple[str, ...]:
    if engine != "auto":
        return (engine,)
    if scanner_name == "prompt_injection":
        return ("regex", "llm_guard")
    if scanner_name == "pii":
        return ("presidio", "regex") if use_presidio else ("regex",)
    if scanner_name == "secrets":
        return ("regex", "llm_guard")
    return ("regex",)


def _scanner_for_engine(scanner_name: str, engine: str, *, use_presidio: bool) -> Scanner | None:
    try:
        if scanner_name == "prompt_injection":
            if engine == "regex":
                return PromptInjectionScanner()
            if engine == "llm_guard":
                return LlmGuardPromptInjectionScanner()
        if scanner_name == "pii":
            if engine == "presidio" and use_presidio:
                return PresidioPiiScanner()
            if engine == "regex":
                return RegexPiiScanner()
        if scanner_name == "secrets":
            if engine == "regex":
                return SecretsScanner()
            if engine == "llm_guard":
                return LlmGuardSecretsScanner()
        if scanner_name == "system_prompt_leakage" and engine == "regex":
            return SystemPromptLeakageScanner()
        if scanner_name == "improper_output" and engine == "regex":
            return ImproperOutputScanner()
    except Exception:
        return None
    return None


def _fallback_scanner(scanner_name: str) -> Scanner:
    scanner = _scanner_for_engine(scanner_name, "regex", use_presidio=False)
    if scanner is None:
        raise ValueError(f"No scanner implementation available for {scanner_name}")
    return scanner
