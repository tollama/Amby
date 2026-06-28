from __future__ import annotations

import re


_SANITIZERS = [
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[REDACTED_EMAIL]"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]{2,}\b", re.I), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b\d{6}-[1-4]\d{6}\b"), "[REDACTED_KR_RRN]"),
    (re.compile(r"\b01[016789]-\d{3,4}-\d{4}\b"), "[REDACTED_KR_PHONE]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b"), "Bearer [REDACTED_SECRET]"),
]


def sanitize_audit_snippet(snippet: str) -> str:
    sanitized = snippet
    for pattern, replacement in _SANITIZERS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized
