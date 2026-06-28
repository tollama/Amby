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
    assert stored["policy_hash"] is None
    assert stored["config_hash"] is None
    assert store.list_events(decision="block")[0]["detections"][0]["asi_id"] == "ASI01"
    assert store.stats_by_asi() == [{"asi_id": "ASI01", "count": 1, "severity": "high"}]
    assert "ASI01" in store.to_csv(store.export_events())


def test_audit_store_records_policy_and_config_hashes(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.initialize()

    store.record_event(
        AuditEventInput(
            request_id="req-hash",
            direction="input",
            upstream_model="gpt-test",
            scanners_run=[],
            detections=[],
            decision="allow",
            latency_ms=1,
            error=None,
            client_meta={},
            policy_hash="policy-hash",
            config_hash="config-hash",
        )
    )

    exported = store.export_events()[0]
    assert exported["policy_hash"] == "policy-hash"
    assert exported["config_hash"] == "config-hash"
    csv_export = store.to_csv([exported])
    assert "policy-hash" in csv_export
    assert "config-hash" in csv_export
