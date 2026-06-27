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

        self._analyzer = AnalyzerEngine()

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=["EMAIL_ADDRESS", "US_SSN", "CREDIT_CARD", "PHONE_NUMBER"],
        )
        spans = [Span(start=item.start, end=item.end, label=item.entity_type) for item in results]
        score = max((float(item.score) for item in results), default=0.0)
        return ScanResult(scanner=self.name, detected=bool(spans), score=score, spans=spans)


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
