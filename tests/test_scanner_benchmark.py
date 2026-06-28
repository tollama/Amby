from app.guardrails.benchmark import run_benchmark


def test_scanner_benchmark_has_no_false_negatives_on_seed_cases() -> None:
    result = run_benchmark()

    assert result["schema_version"] == "amby.scanner_benchmark.v1"
    assert result["false_negative"] == 0
    assert result["false_positive_rate"] == 0
    assert result["recall"] == 1.0
