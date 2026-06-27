from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

from app.config import AppConfig, AuditConfig, PolicyConfig, ScannerRule, ServerConfig, UpstreamConfig
from app.evidence.generator import EvidenceOptions, generate_evidence_package
from app.main import create_app
from app.proxy.upstream import UpstreamTarget


RAW_EMAIL = "very.private.customer@example.com"
RAW_SSN = "123-45-6789"
RAW_SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890"


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        server=ServerConfig(port=8080, dashboard=True),
        upstreams=[UpstreamConfig(match="gpt-*", provider="openai", base_url="https://mock.openai.local")],
        policy=PolicyConfig(
            on_error="fail_open",
            input={
                "prompt_injection": ScannerRule(action="block", threshold=0.8),
                "pii": ScannerRule(action="flag", threshold=0.5),
                "secrets": ScannerRule(action="block", threshold=0.5),
            },
            output={
                "pii": ScannerRule(action="redact", threshold=0.5),
                "secrets": ScannerRule(action="block", threshold=0.5),
            },
        ),
        audit=AuditConfig(store=str(tmp_path / "audit.db"), retention_days=90),
    )


def test_audit_exports_and_evidence_do_not_store_raw_pii_or_secret(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    async def fake_post_json(target: UpstreamTarget, payload: dict[str, Any]) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-privacy",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": f"Customer {RAW_EMAIL} has SSN {RAW_SSN}.",
                        }
                    }
                ],
            },
        )

    monkeypatch.setattr("app.main.post_json", fake_post_json)
    config = _config(tmp_path)
    client = TestClient(create_app(config))

    output_response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-test", "messages": [{"role": "user", "content": "Review customer."}]},
    )
    secret_response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-test", "messages": [{"role": "user", "content": f"Use token {RAW_SECRET}."}]},
    )

    assert output_response.status_code == 200
    assert RAW_EMAIL not in output_response.text
    assert RAW_SSN not in output_response.text
    assert secret_response.status_code == 403

    exported_json = client.get("/audit/export?format=json").text
    exported_csv = client.get("/audit/export?format=csv").text
    for exported in (exported_json, exported_csv):
        assert RAW_EMAIL not in exported
        assert RAW_SSN not in exported
        assert RAW_SECRET not in exported
        assert "[REDACTED_EMAIL]" in exported
        assert "[REDACTED_SECRET]" in exported

    manifest = generate_evidence_package(
        EvidenceOptions(
            db_path=config.audit.store,
            config_path=str(tmp_path / "missing-config.yaml"),
            output_root=str(tmp_path / "evidence"),
            generated_at="2026-06-27T000000Z",
            package_name="privacy-proof",
        )
    )
    package_dir = Path(manifest["package_dir"])
    for path in package_dir.iterdir():
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            assert RAW_EMAIL not in content
            assert RAW_SSN not in content
            assert RAW_SECRET not in content

    for db_artifact in tmp_path.glob("audit.db*"):
        content = db_artifact.read_bytes()
        assert RAW_EMAIL.encode() not in content
        assert RAW_SSN.encode() not in content
        assert RAW_SECRET.encode() not in content
