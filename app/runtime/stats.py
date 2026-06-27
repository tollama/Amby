from __future__ import annotations

from typing import Any

from app.evidence.generator import build_evidence_stats


def build_runtime_stats(events: list[dict[str, Any]]) -> dict[str, Any]:
    evidence_stats = build_evidence_stats(events)
    latencies = sorted(int(event.get("latency_ms") or 0) for event in events)
    scanner_stats = _scanner_stats(events)
    errors = [str(event.get("error")) for event in events if event.get("error")]
    return {
        "schema_version": "amby.runtime_stats.v1",
        "events": {
            "total": evidence_stats["events"],
            "decisions": evidence_stats["decisions"],
            "directions": evidence_stats["directions"],
        },
        "latency_ms": {
            "count": len(latencies),
            "p50": _percentile(latencies, 50),
            "p95": _percentile(latencies, 95),
            "max": max(latencies, default=0),
        },
        "errors": {
            "total": len(errors),
            "samples": errors[:5],
        },
        "scanners": scanner_stats,
    }


def _scanner_stats(events: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = {}
    for event in events:
        for scanner in event.get("scanners_run", []):
            item = stats.setdefault(str(scanner), {"runs": 0, "detections": 0, "errors": 0})
            item["runs"] += 1
        for detection in event.get("detections", []):
            scanner = str(detection.get("scanner") or "unknown")
            item = stats.setdefault(scanner, {"runs": 0, "detections": 0, "errors": 0})
            item["detections"] += 1
        error = event.get("error")
        if isinstance(error, str) and error:
            for scanner in _scanner_names_from_error(error):
                item = stats.setdefault(scanner, {"runs": 0, "detections": 0, "errors": 0})
                item["errors"] += 1
    return dict(sorted(stats.items()))


def _scanner_names_from_error(error: str) -> list[str]:
    names: list[str] = []
    for part in error.split(";"):
        scanner = part.strip().split(":", 1)[0].strip()
        if scanner:
            names.append(scanner)
    return names or ["unknown"]


def _percentile(values: list[int], percentile: int) -> int:
    if not values:
        return 0
    if len(values) == 1:
        return values[0]
    rank = (len(values) - 1) * (percentile / 100)
    lower = int(rank)
    upper = min(lower + 1, len(values) - 1)
    weight = rank - lower
    return round(values[lower] * (1 - weight) + values[upper] * weight)
