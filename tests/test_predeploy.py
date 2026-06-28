from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.audit.store import AuditStore
from app.config import AppConfig, AuditConfig, PolicyConfig, ScannerRule, ServerConfig, UpstreamConfig, parse_config
from app.evidence.generator import EvidenceOptions, generate_evidence_package, verify_evidence_package
from app.main import create_app
from app.predeploy.aibom import generate_aibom
from app.predeploy.adapters import CommandExecutor, PredeployAdapterRunner
from app.predeploy.normalizers import normalize_garak_output, normalize_promptfoo_output, normalize_pyrit_output
from app.predeploy.runner import PredeployRunner, should_fail_ci
from app.predeploy.types import CommandResult


RAW_SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
RAW_MODEL_OUTPUT = "model leaked private output"


class FakeExecutor(CommandExecutor):
    def __init__(self, result: CommandResult) -> None:
        self.result = result

    def run(self, command: tuple[str, ...], *, cwd: Path, timeout_seconds: int) -> CommandResult:
        return self.result


def _base_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        server=ServerConfig(port=8080, dashboard=True),
        upstreams=[UpstreamConfig(match="gpt-*", provider="openai", base_url="https://mock.openai.local")],
        policy=PolicyConfig(
            on_error="fail_open",
            input={"prompt_injection": ScannerRule(action="block", threshold=0.8)},
            output={"secrets": ScannerRule(action="block", threshold=0.5)},
        ),
        audit=AuditConfig(store=str(tmp_path / "audit.db"), retention_days=90),
    )


def _predeploy_config(tmp_path: Path, *, decision_stdout: str | None = None) -> AppConfig:
    return parse_config(
        {
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://mock.openai.local"}],
            "policy": {
                "on_error": "fail_open",
                "input": {"prompt_injection": {"action": "block", "threshold": 0.8}},
                "output": {"secrets": {"action": "block", "threshold": 0.5}},
            },
            "audit": {"store": str(tmp_path / "audit.db"), "retention_days": 90},
            "predeploy": {
                "enabled": True,
                "suite": "default",
                "ci_gate": True,
                "output_root": str(tmp_path / "predeploy"),
                "adapters": {
                    "garak": {"enabled": True, "command": ["fake-garak"], "timeout_seconds": 5, "output_format": "json"},
                    "pyrit": {"enabled": False},
                    "promptfoo": {"enabled": False},
                },
                "targets": {"model": "gpt-*", "promptfooconfig": "promptfooconfig.yaml"},
            },
        }
    )


def test_parse_config_accepts_predeploy() -> None:
    config = parse_config(
        {
            "upstreams": [{"match": "gpt-*", "provider": "openai", "base_url": "https://example.com"}],
            "policy": {"on_error": "fail_open", "input": {}, "output": {}},
            "audit": {"store": "./data/audit.db", "retention_days": 90},
            "predeploy": {
                "enabled": True,
                "suite": "default",
                "thresholds": {"max_fail_findings": 0, "max_error_findings": 0},
                "adapters": {"garak": {"enabled": True, "command": ["python", "-m", "garak"]}},
                "targets": {"model": "gpt-*", "checks": ["prompt_injection"]},
            },
        }
    )

    assert config.predeploy.enabled is True
    assert config.predeploy.adapters["garak"].command == ("python", "-m", "garak")
    assert config.predeploy.adapters["promptfoo"].enabled is True
    assert config.predeploy.targets["checks"] == ["prompt_injection"]


def test_adapter_output_normalization() -> None:
    garak = normalize_garak_output('{"probe":"prompt_injection","status":"failed","score":1.0,"description":"bypass"}')
    pyrit = normalize_pyrit_output('{"objective":"unsafe tool call","score_value":0.9,"risk":"high"}')
    promptfoo = normalize_promptfoo_output('{"results":[{"success":false,"test":{"description":"leakage","metadata":{"control":"leakage"}}}]}')

    assert garak[0].decision == "fail"
    assert garak[0].asi_id == "ASI01"
    assert pyrit[0].control == "unsafe_tool_use"
    assert promptfoo[0].control == "leakage"
    assert promptfoo[0].decision == "fail"


def test_predeploy_runner_records_fail_findings_and_ci_gate(tmp_path: Path) -> None:
    config = _predeploy_config(tmp_path)
    result = CommandResult(
        command=("fake-garak",),
        exit_code=0,
        stdout='{"probe":"prompt_injection","status":"failed","score":1.0,"description":"bypass worked"}',
        stderr="",
        duration_ms=3,
    )
    runner = PredeployRunner(
        config,
        adapter_runner=PredeployAdapterRunner(executor=FakeExecutor(result), workspace_root=tmp_path),
        workspace_root=tmp_path,
    )

    run = runner.run()
    store = AuditStore(config.audit.store)
    runs = store.list_predeploy_runs(limit=10)
    findings = store.list_predeploy_findings(run_id=run.run_id, limit=10)

    assert run.decision == "fail"
    assert should_fail_ci(run, config) is True
    assert runs[0]["decision"] == "fail"
    assert any(finding["decision"] == "fail" and finding["asi_id"] == "ASI01" for finding in findings)
    assert (Path(run.output_dir) / "tool_outputs" / "garak.json").exists()


def test_predeploy_fixture_run_api(tmp_path: Path) -> None:
    client = TestClient(create_app(_predeploy_config(tmp_path)))

    response = client.post("/predeploy/run", json={"use_fixtures": True, "out": str(tmp_path / "predeploy")})
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "pass"
    assert payload["adapter_status"]["garak"] == "pass"

    runs = client.get("/predeploy/runs").json()
    findings = client.get(f"/predeploy/findings?run_id={payload['run_id']}").json()
    assert runs[0]["id"] == payload["run_id"]
    assert findings
    assert all(finding["decision"] == "pass" for finding in findings)


def test_aibom_generation_does_not_store_raw_secret_or_model_output(tmp_path: Path) -> None:
    (tmp_path / "promptfooconfig.yaml").write_text(
        f"description: {RAW_SECRET}\n# {RAW_MODEL_OUTPUT}\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\ndependencies=["fastapi>=0.1"]\n',
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        '{"devDependencies":{"promptfoo":"^0.118.0"},"engines":{"node":"^20.20.0 || >=22.22.0"}}',
        encoding="utf-8",
    )
    config = _base_config(tmp_path)

    aibom = generate_aibom(config, workspace_root=tmp_path)
    serialized = json.dumps(aibom, sort_keys=True)

    assert aibom["privacy"]["stores_raw_secrets"] is False
    assert "promptfooconfig.yaml" in serialized
    assert RAW_SECRET not in serialized
    assert RAW_MODEL_OUTPUT not in serialized
    assert "promptfoo" in serialized


def test_evidence_package_includes_predeploy_chain_and_aibom(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    store = AuditStore(config.audit.store)
    runner = PredeployRunner(config, audit_store=store, workspace_root=tmp_path)
    runner.run(output_root=tmp_path / "predeploy", use_fixtures=True)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"audit:\n  store: {config.audit.store}\n", encoding="utf-8")

    manifest = generate_evidence_package(
        EvidenceOptions(
            db_path=config.audit.store,
            config_path=str(config_path),
            output_root=str(tmp_path / "evidence"),
            generated_at="2026-06-28T000000Z",
            package_name="proof",
        )
    )
    package_dir = Path(manifest["package_dir"])

    assert (package_dir / "predeploy_runs.jsonl").exists()
    assert (package_dir / "predeploy_findings.jsonl").exists()
    assert (package_dir / "predeploy_chain.jsonl").exists()
    assert (package_dir / "control_plane.json").exists()
    assert (package_dir / "control_plane_chain.jsonl").exists()
    assert (package_dir / "aibom.json").exists()
    assert (package_dir / "tool_outputs" / "manifest.json").exists()
    assert "Pre-deploy Governance" in (package_dir / "report.md").read_text(encoding="utf-8")

    mythos = json.loads((package_dir / "mythos_ready.json").read_text(encoding="utf-8"))
    assert mythos["runtime_evidence"]["predeploy_run_count"] == 1
    assert any(control["control_id"] == "MYTHOS-01" and control["evidence_present"] for control in mythos["controls"])
    verification = verify_evidence_package(package_dir)
    assert verification["valid"] is True
    assert verification["predeploy_chain"]["valid"] is True
    assert verification["control_plane_chain"]["valid"] is True
