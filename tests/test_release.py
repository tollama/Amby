from __future__ import annotations

import json
from pathlib import Path

from app.config import parse_config
from app.release.metadata import build_release_manifest, evaluate_docker_smoke, generate_release_sbom


RAW_TOKEN = "raw-release-token"
RAW_SIGNING_KEY = "raw-policy-signing-key"


def test_release_sbom_includes_python_node_and_docker_metadata_without_secrets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("AMBY_API_TOKEN", RAW_TOKEN)
    monkeypatch.setenv("AMBY_POLICY_SIGNING_KEY", RAW_SIGNING_KEY)
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "amby-test"
version = "0.1.0"
dependencies = ["fastapi>=0.115"]

[project.optional-dependencies]
dev = ["pytest"]
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "fastapi"
version = "0.115.0"
""",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "amby-node", "version": "0.1.0", "dependencies": {"promptfoo": "^1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/promptfoo": {"version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim\nHEALTHCHECK CMD python -c 'pass'\nUSER amby\n",
        encoding="utf-8",
    )

    sbom = generate_release_sbom(project_root=tmp_path, docker_metadata={"image_tag": "amby:rc"})
    serialized = json.dumps(sbom, sort_keys=True)

    assert sbom["python"]["project_name"] == "amby-test"
    assert sbom["python"]["locked_packages"][0]["name"] == "fastapi"
    assert sbom["node"]["dependencies"][0]["name"] == "promptfoo"
    assert sbom["docker"]["base_image"] == "python:3.11-slim"
    assert sbom["docker"]["non_root_user"] == "amby"
    assert sbom["docker"]["has_healthcheck"] is True
    assert RAW_TOKEN not in serialized
    assert RAW_SIGNING_KEY not in serialized


def test_release_manifest_excludes_raw_tokens_and_signing_keys(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AMBY_API_TOKEN", RAW_TOKEN)
    monkeypatch.setenv("AMBY_POLICY_SIGNING_KEY", RAW_SIGNING_KEY)
    config = parse_config(
        {
            "deployment": {"mode": "production"},
            "security": {
                "api_auth": {"enabled": True, "token_env": "AMBY_API_TOKEN"},
                "dashboard_auth": {"enabled": True, "token_env": "AMBY_DASHBOARD_TOKEN"},
            },
            "control_plane": {"policy_signing": {"enabled": True, "key_env": "AMBY_POLICY_SIGNING_KEY"}},
            "evidence": {"ledger": {"enabled": True, "path": str(tmp_path / "ledger.jsonl")}},
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {"on_error": "fail_open", "input": {"prompt_injection": {"action": "block"}}, "output": {}},
            "audit": {"store": str(tmp_path / "audit.db"), "retention_days": 90},
            "predeploy": {"enabled": True, "ci_gate": True},
        }
    )
    checks = {
        "tests": {"decision": "pass"},
        "predeploy": {"decision": "pass"},
        "control_plane_drift": {"decision": "pass"},
        "evidence_verify": {"decision": "pass"},
        "diagnostics": {"decision": "pass"},
        "docker_smoke": {"decision": "pass"},
    }

    manifest = build_release_manifest(
        config=config,
        config_path="config.production.yaml",
        db_path=str(tmp_path / "audit.db"),
        bundle_dir=str(tmp_path),
        evidence_package=str(tmp_path / "evidence"),
        checks=checks,
        image_tag="amby:rc",
        image_id="sha256:test",
        docker_smoke={"decision": "pass", "status": "ok"},
    )
    serialized = json.dumps(manifest, sort_keys=True)

    assert manifest["decision"] == "pass"
    assert RAW_TOKEN not in serialized
    assert RAW_SIGNING_KEY not in serialized
    assert manifest["privacy"]["stores_raw_secrets"] is False


def test_docker_smoke_fails_when_production_diagnostics_not_ok() -> None:
    smoke = evaluate_docker_smoke(
        healthz={"status": "ok"},
        diagnostics={
            "status": "blocked",
            "deployment": {"mode": "production", "production_ready": False},
            "config_hash": "c" * 64,
            "policy_hash": "p" * 64,
        },
        raw_secret_values=[RAW_TOKEN],
    )

    assert smoke["decision"] == "fail"
    assert smoke["diagnostics"]["status"] == "blocked"
