from app.runtime.stats import build_runtime_stats


def test_runtime_stats_summarizes_latency_decisions_and_errors() -> None:
    stats = build_runtime_stats(
        [
            {
                "decision": "allow",
                "direction": "input",
                "latency_ms": 1,
                "scanners_run": ["prompt_injection"],
                "detections": [],
                "error": None,
            },
            {
                "decision": "redact",
                "direction": "output",
                "latency_ms": 9,
                "scanners_run": ["pii"],
                "detections": [{"scanner": "pii", "asi_id": "ASI09"}],
                "error": "pii: RuntimeError: scanner warning",
            },
        ]
    )

    assert stats["schema_version"] == "amby.runtime_stats.v1"
    assert stats["events"]["total"] == 2
    assert stats["events"]["decisions"]["redact"] == 1
    assert stats["latency_ms"]["p50"] == 5
    assert stats["latency_ms"]["p95"] == 9
    assert stats["errors"]["total"] == 1
    assert stats["scanners"]["pii"]["detections"] == 1
    assert stats["scanners"]["pii"]["errors"] == 1
