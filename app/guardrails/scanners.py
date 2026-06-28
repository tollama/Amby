from __future__ import annotations

import re

from app.guardrails.types import ScanContext, ScanResult, Span


class PromptInjectionScanner:
    name = "prompt_injection"

    _patterns = [
        (re.compile(r"\bignore (all )?(previous|prior|above) (instructions|rules)\b", re.I), 0.95),
        (re.compile(r"\bdisregard (all )?(previous|prior|above) (instructions|rules)\b", re.I), 0.95),
        (re.compile(r"\breveal (the )?(system|developer|hidden) (prompt|instructions)\b", re.I), 0.92),
        (re.compile(r"\bprint (the )?(system|developer|hidden) (prompt|instructions)\b", re.I), 0.9),
        (re.compile(r"\bjailbreak\b|\bDAN mode\b|\bdeveloper mode\b", re.I), 0.88),
        (re.compile(r"\bdisable (your )?(safety|guardrails|policy|filters)\b", re.I), 0.86),
        (re.compile(r"\byou are now\b.+\b(no restrictions|unfiltered|developer mode)\b", re.I | re.S), 0.84),
        (re.compile(r"\bexfiltrate\b.+\b(secret|credential|token|key|password)s?\b", re.I | re.S), 0.92),
        (re.compile(r"(이전|위의|앞의)\s*(지시|명령|규칙).{0,12}(무시|잊어|따르지)", re.I | re.S), 0.95),
        (re.compile(r"(시스템|개발자|숨겨진)\s*(프롬프트|지시|명령).{0,12}(공개|출력|보여)", re.I | re.S), 0.93),
        (re.compile(r"(탈옥|제일브레이크|개발자\s*모드|제한\s*없이)", re.I), 0.88),
    ]

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        spans: list[Span] = []
        score = 0.0
        for pattern, pattern_score in self._patterns:
            for match in pattern.finditer(text):
                spans.append(Span(start=match.start(), end=match.end(), label="PROMPT_INJECTION"))
                score = max(score, pattern_score)
        return ScanResult(scanner=self.name, detected=bool(spans), score=score, spans=spans)


class RegexPiiScanner:
    name = "pii"

    _patterns = [
        ("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), 0.95),
        ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.95),
        ("KR_RRN", re.compile(r"\b\d{6}-[1-4]\d{6}\b"), 0.95),
        ("KR_PHONE", re.compile(r"\b01[016789]-\d{3,4}-\d{4}\b"), 0.88),
    ]

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        spans: list[Span] = []
        score = 0.0
        for label, pattern, pattern_score in self._patterns:
            for match in pattern.finditer(text):
                spans.append(Span(start=match.start(), end=match.end(), label=label))
                score = max(score, pattern_score)
        return ScanResult(scanner=self.name, detected=bool(spans), score=score, spans=spans)


class PresidioPiiScanner:
    name = "pii"

    def __init__(self) -> None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=["EMAIL_ADDRESS", "US_SSN", "CREDIT_CARD", "PHONE_NUMBER"],
        )
        spans = [Span(start=item.start, end=item.end, label=item.entity_type) for item in results]
        score = max((float(item.score) for item in results), default=0.0)
        return ScanResult(scanner=self.name, detected=bool(spans), score=score, spans=spans)


class LlmGuardPromptInjectionScanner:
    name = "prompt_injection"

    def __init__(self) -> None:
        from llm_guard.input_scanners import PromptInjection

        self._scanner = PromptInjection()

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        detected, score = _scan_with_llm_guard(self._scanner, text)
        spans = [Span(start=0, end=len(text), label="PROMPT_INJECTION")] if detected else []
        return ScanResult(scanner=self.name, detected=detected, score=score, spans=spans)


class SecretsScanner:
    name = "secrets"

    _patterns = [
        ("OPENAI_API_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 0.98),
        ("ANTHROPIC_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0.98),
        ("AWS_ACCESS_KEY", re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b"), 0.98),
        ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), 0.96),
        ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I), 0.99),
        ("BEARER_TOKEN", re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{24,})\b"), 0.9),
        (
            "NAMED_SECRET",
            re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{24,})"),
            0.9,
        ),
    ]

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        spans: list[Span] = []
        score = 0.0
        for label, pattern, pattern_score in self._patterns:
            for match in pattern.finditer(text):
                if label in {"BEARER_TOKEN", "NAMED_SECRET"} and match.lastindex:
                    start, end = match.span(match.lastindex)
                else:
                    start, end = match.span()
                spans.append(Span(start=start, end=end, label=label))
                score = max(score, pattern_score)
        return ScanResult(scanner=self.name, detected=bool(spans), score=score, spans=spans)


class LlmGuardSecretsScanner:
    name = "secrets"

    def __init__(self) -> None:
        from llm_guard.input_scanners import Secrets

        self._scanner = Secrets()

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        detected, score = _scan_with_llm_guard(self._scanner, text)
        spans = [Span(start=0, end=len(text), label="SECRET")] if detected else []
        return ScanResult(scanner=self.name, detected=detected, score=score, spans=spans)


class SystemPromptLeakageScanner:
    name = "system_prompt_leakage"

    _patterns = [
        ("SYSTEM_PROMPT", re.compile(r"\b(system|developer|hidden)\s+(prompt|instructions?)\b", re.I), 0.88),
        ("POLICY_DISCLOSURE", re.compile(r"\b(confidential|internal)\s+(policy|instruction|chain[- ]of[- ]thought)\b", re.I), 0.86),
        ("KOREAN_SYSTEM_PROMPT", re.compile(r"(시스템|개발자|숨겨진)\s*(프롬프트|지시|명령)", re.I), 0.88),
    ]

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        spans: list[Span] = []
        score = 0.0
        for label, pattern, pattern_score in self._patterns:
            for match in pattern.finditer(text):
                spans.append(Span(start=match.start(), end=match.end(), label=label))
                score = max(score, pattern_score)
        return ScanResult(scanner=self.name, detected=bool(spans), score=score, spans=spans)


class ImproperOutputScanner:
    name = "improper_output"

    _patterns = [
        ("SCRIPT_TAG", re.compile(r"<\s*script\b", re.I), 0.9),
        ("JS_URL", re.compile(r"\bjavascript\s*:", re.I), 0.9),
        ("HTML_EVENT_HANDLER", re.compile(r"\bon(?:error|load|click)\s*=", re.I), 0.86),
        ("DANGEROUS_SHELL", re.compile(r"\b(rm\s+-rf\s+/|curl\s+[^|\n]+\|\s*sh|wget\s+[^|\n]+\|\s*sh)\b", re.I), 0.92),
        ("DANGEROUS_SQL", re.compile(r"\b(drop\s+table|truncate\s+table)\b", re.I), 0.84),
    ]

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        spans: list[Span] = []
        score = 0.0
        for label, pattern, pattern_score in self._patterns:
            for match in pattern.finditer(text):
                spans.append(Span(start=match.start(), end=match.end(), label=label))
                score = max(score, pattern_score)
        return ScanResult(scanner=self.name, detected=bool(spans), score=score, spans=spans)


def _scan_with_llm_guard(scanner: object, text: str) -> tuple[bool, float]:
    result = scanner.scan(text)  # type: ignore[attr-defined]
    if isinstance(result, tuple):
        if len(result) >= 3:
            _, is_valid, risk_score = result[:3]
            return (not bool(is_valid), float(risk_score))
        if len(result) == 2:
            is_valid, risk_score = result
            return (not bool(is_valid), float(risk_score))
    if isinstance(result, dict):
        if "is_valid" in result:
            return (not bool(result["is_valid"]), float(result.get("risk_score", result.get("score", 1.0))))
        if "detected" in result:
            return (bool(result["detected"]), float(result.get("score", 1.0)))
    return (False, 0.0)
