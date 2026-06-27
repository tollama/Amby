from pathlib import Path

from app.audit.store import AuditEventInput, AuditStore
from app.evidence.generator import EvidenceOptions, generate_evidence_package, verify_evidence_package


def test_evidence_package_generation_and_verification(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text("audit:\n  store: audit.db\n", encoding="utf-8")

    store = AuditStore(str(db_path))
    store.initialize()
    store.record_event(
        AuditEventInput(
            request_id="req-evidence",
            direction="output",
            upstream_model="gpt-test",
            scanners_run=["pii"],
            detections=[
                {
                    "scanner": "pii",
                    "asi_id": "ASI09",
                    "severity": "medium",
                    "score": 0.95,
                    "action": "redact",
                    "snippet_masked": "Contact [REDACTED_EMAIL].",
                }
            ],
            decision="redact",
            latency_ms=2,
            error=None,
            client_meta={"ip_hash": "abc"},
        )
    )

    manifest = generate_evidence_package(
        EvidenceOptions(
            db_path=str(db_path),
            config_path=str(config_path),
            output_root=str(tmp_path / "evidence"),
            generated_at="2026-06-27T000000Z",
            package_name="proof",
        )
    )
    package_dir = Path(manifest["package_dir"])

    assert (package_dir / "report.md").exists()
    assert (package_dir / "manifest.json").exists()
    assert (package_dir / "audit_events.jsonl").exists()
    assert "ASI09" in (package_dir / "report.md").read_text(encoding="utf-8")

    verification = verify_evidence_package(package_dir)
    assert verification["valid"] is True
