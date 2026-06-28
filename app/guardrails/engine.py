from __future__ import annotations

import time
from collections import defaultdict

from app.audit.sanitize import sanitize_audit_snippet
from app.asi.mapping import mapping_for
from app.config import PolicyConfig
from app.guardrails.types import GuardrailDecision, ScanContext, Scanner, Span
from app.policy.policy import PolicyEngine, stronger_decision


class GuardrailEngine:
    def __init__(self, policy: PolicyConfig, scanners: dict[str, Scanner]) -> None:
        self.policy = PolicyEngine(policy)
        self.scanners = scanners

    def scan_texts(
        self,
        texts: list[str],
        *,
        direction: str,
        model: str,
        request_id: str,
    ) -> GuardrailDecision:
        started = time.perf_counter()
        decision = "allow"
        scanners_run: list[str] = []
        detections: list[dict[str, object]] = []
        redact_spans: list[Span] = []
        errors: list[str] = []
        ctx = ScanContext(request_id=request_id, direction=direction, model=model)

        for scanner_name, scanner in self.scanners.items():
            rule = self.policy.rule_for(direction, scanner_name)
            if rule.action == "off":
                continue

            scanners_run.append(scanner_name)
            try:
                scanner_started = time.perf_counter()
                scanner_spans: list[Span] = []
                scanner_score = 0.0
                for segment_index, text in enumerate(texts):
                    if not text:
                        continue
                    result = scanner.scan(text, ctx)
                    if not result.detected or result.score < rule.threshold:
                        continue
                    scanner_score = max(scanner_score, result.score)
                    scanner_spans.extend(
                        Span(
                            start=span.start,
                            end=span.end,
                            label=span.label,
                            segment_index=segment_index,
                        )
                        for span in result.spans
                    )

                scanner_latency_ms = int((time.perf_counter() - scanner_started) * 1000)
                if scanner_latency_ms > rule.timeout_ms:
                    errors.append(f"{scanner_name}: TimeoutError: scanner exceeded {rule.timeout_ms} ms budget")
                    if self.policy.on_error == "fail_closed":
                        decision = stronger_decision(decision, "block")
                    continue

                if not scanner_spans:
                    continue

                asi = mapping_for(scanner_name)
                decision = stronger_decision(decision, rule.action if rule.action != "off" else "allow")
                if rule.action == "redact":
                    redact_spans.extend(scanner_spans)

                for span in scanner_spans[:8]:
                    detections.append(
                        {
                            "scanner": scanner_name,
                            "asi_id": asi.asi_id,
                            "llm_id": asi.llm_id,
                            "owasp_llm": list(asi.owasp_llm),
                            "owasp_asi": list(asi.owasp_asi),
                            "nist_rmf": list(asi.nist_rmf),
                            "nist_genai": list(asi.nist_genai),
                            "severity": asi.severity,
                            "score": round(scanner_score, 4),
                            "action": rule.action,
                            "label": span.label,
                            "scanner_engine": rule.engine,
                            "scanner_latency_ms": scanner_latency_ms,
                            "snippet_masked": _masked_snippet(texts[span.segment_index], span),
                        }
                    )
            except Exception as exc:
                errors.append(f"{scanner_name}: {type(exc).__name__}: {exc}")
                if self.policy.on_error == "fail_closed":
                    decision = stronger_decision(decision, "block")

        output_texts = list(texts)
        if decision != "block" and redact_spans:
            output_texts = _apply_redactions(texts, redact_spans)

        latency_ms = int((time.perf_counter() - started) * 1000)
        return GuardrailDecision(
            decision=decision,
            scanners_run=scanners_run,
            detections=detections,
            texts=output_texts,
            latency_ms=latency_ms,
            error="; ".join(errors) if errors else None,
        )


def _apply_redactions(texts: list[str], spans: list[Span]) -> list[str]:
    grouped: dict[int, list[Span]] = defaultdict(list)
    for span in spans:
        grouped[span.segment_index].append(span)

    output = list(texts)
    for segment_index, segment_spans in grouped.items():
        text = output[segment_index]
        for span in sorted(_coalesce_spans(segment_spans), key=lambda item: item.start, reverse=True):
            text = text[: span.start] + _mask_for(span.label) + text[span.end :]
        output[segment_index] = text
    return output


def _coalesce_spans(spans: list[Span]) -> list[Span]:
    if not spans:
        return []

    sorted_spans = sorted(spans, key=lambda span: (span.start, span.end))
    merged = [sorted_spans[0]]
    for span in sorted_spans[1:]:
        previous = merged[-1]
        if span.start <= previous.end:
            merged[-1] = Span(
                start=previous.start,
                end=max(previous.end, span.end),
                label=previous.label if previous.label == span.label else "SENSITIVE",
                segment_index=previous.segment_index,
            )
        else:
            merged.append(span)
    return merged


def _mask_for(label: str) -> str:
    normalized = label.upper().replace(" ", "_")
    if "EMAIL" in normalized:
        return "[REDACTED_EMAIL]"
    if "SSN" in normalized:
        return "[REDACTED_SSN]"
    if "SECRET" in normalized or "KEY" in normalized or "TOKEN" in normalized or "PASSWORD" in normalized:
        return "[REDACTED_SECRET]"
    return f"[REDACTED_{normalized}]"


def _masked_snippet(text: str, span: Span, radius: int = 32) -> str:
    marker = "[[AMBY_CURRENT_FINDING]]"
    masked_text = text[: span.start] + marker + text[span.end :]
    sanitized = sanitize_audit_snippet(masked_text).replace(marker, _mask_for(span.label))
    marker_index = sanitized.find(_mask_for(span.label))
    if marker_index < 0:
        marker_index = min(span.start, len(sanitized))
    start = max(0, marker_index - radius)
    end = min(len(sanitized), marker_index + len(_mask_for(span.label)) + radius)
    return " ".join(sanitized[start:end].split())
