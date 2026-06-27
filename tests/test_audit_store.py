from app.audit.store import AuditEventInput, AuditStore


def test_audit_store_records_and_exports_events(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.initialize()

    stored = store.record_event(
        AuditEventInput(
            request_id="req-1",
            direction="input",
            upstream_model="gpt-test",
            scanners_run=["prompt_injection"],
            detections=[
                {
                    "scanner": "prompt_injection",
                    "asi_id": "ASI01",
                    "severity": "high",
                    "score": 0.95,
                    "action": "block",
                    "snippet_masked": "[REDACTED_PROMPT_INJECTION]",
                }
            ],
            decision="block",
            latency_ms=3,
            error=None,
            client_meta={"ip_hash": "abc"},
        )
    )

    assert stored["request_id"] == "req-1"
    assert store.list_events(decision="block")[0]["detections"][0]["asi_id"] == "ASI01"
    assert store.stats_by_asi() == [{"asi_id": "ASI01", "count": 1, "severity": "high"}]
    assert "ASI01" in store.to_csv(store.export_events())
