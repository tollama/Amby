from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class ScanContext:
    request_id: str
    direction: str
    model: str


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    label: str
    segment_index: int = 0


@dataclass(frozen=True)
class ScanResult:
    scanner: str
    detected: bool
    score: float
    spans: list[Span] = field(default_factory=list)


class Scanner(Protocol):
    name: str

    def scan(self, text: str, ctx: ScanContext) -> ScanResult:
        ...


@dataclass(frozen=True)
class GuardrailDecision:
    decision: str
    scanners_run: list[str]
    detections: list[dict[str, object]]
    texts: list[str]
    latency_ms: int
    error: str | None = None
