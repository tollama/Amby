from pathlib import Path

from fastapi.testclient import TestClient

from app.asi.mapping import coverage_matrix
from app.audit.store import AuditEventInput, AuditStore
from app.config import AppConfig, AuditConfig, PolicyConfig, ServerConfig, UpstreamConfig
from app.evidence.generator import build_evidence_stats
from app.main import create_app


def test_coverage_matrix_marks_llm05_and_llm07_implemented() -> None:
    coverage = coverage_matrix()

    statuses = {item["id"]: item["status"] for item in coverage["items"]}
    assert statuses["LLM04"] == "partial"
    assert statuses["LLM05"] == "implemented"
    assert statuses["LLM07"] == "implemented"
    assert statuses["LLM08"] == "partial"
    assert coverage["status_counts"]["implemented"] >= 5


def test_stats_coverage_endpoint(tmp_path: Path) -> None:
    config = AppConfig(
        server=ServerConfig(port=8080, dashboard=True),
        upstreams=[UpstreamConfig(match="gpt-*", provider="openai", base_url="https://mock.openai.local")],
        policy=PolicyConfig(on_error="fail_open", input={}, output={}),
        audit=AuditConfig(store=str(tmp_path / "audit.db"), retention_days=90),
    )
    client = TestClient(create_app(config))

    payload = client.get("/stats/coverage").json()

    assert payload["schema_version"] == "amby.coverage.v1"
    assert any(item["id"] == "LLM01" for item in payload["items"])


def test_evidence_stats_include_framework_counts(tmp_path: Path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.initialize()
    store.record_event(
        AuditEventInput(
            request_id="req-framework",
            direction="output",
            upstream_model="gpt-test",
            scanners_run=["improper_output"],
            detections=[
                {
                    "scanner": "improper_output",
                    "asi_id": "ASI08",
                    "llm_id": "LLM05",
                    "owasp_llm": ["LLM05"],
                    "owasp_asi": ["ASI08"],
                    "nist_rmf": ["MEASURE", "MANAGE"],
                    "nist_genai": ["information-integrity"],
                    "severity": "medium",
                    "score": 0.9,
                    "action": "flag",
                    "snippet_masked": "<script>",
                }
            ],
            decision="flag",
            latency_ms=1,
            error=None,
            client_meta={},
        )
    )

    stats = build_evidence_stats(store.export_events())

    assert stats["frameworks"]["owasp_llm"] == {"LLM05": 1}
    assert stats["frameworks"]["nist_rmf"] == {"MANAGE": 1, "MEASURE": 1}
