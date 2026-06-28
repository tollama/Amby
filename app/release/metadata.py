from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app import __version__
from app.config import AppConfig, config_hash, load_config, policy_hash


RELEASE_SCHEMA_VERSION = "amby.release_candidate.v1"


def write_release_candidate(
    *,
    config_path: str,
    db_path: str,
    bundle_dir: str,
    evidence_package: str,
    image_tag: str | None = None,
    image_id: str | None = None,
    docker_smoke_path: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    root = Path.cwd()
    bundle = Path(bundle_dir)
    bundle.mkdir(parents=True, exist_ok=True)
    generated = generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    image_tag = image_tag or None
    image_id = image_id or None
    config = load_config(config_path)
    docker_smoke = _read_json_file(Path(docker_smoke_path)) if docker_smoke_path else _default_docker_smoke()
    checks = collect_release_checks(bundle, docker_smoke=docker_smoke)
    docker_metadata = {
        "image_tag": image_tag,
        "image_id": image_id,
        "smoke": docker_smoke,
    }
    manifest = build_release_manifest(
        config=config,
        config_path=config_path,
        db_path=db_path,
        bundle_dir=str(bundle),
        evidence_package=evidence_package,
        checks=checks,
        image_tag=image_tag,
        image_id=image_id,
        docker_smoke=docker_smoke,
        generated_at=generated,
    )
    sbom = generate_release_sbom(project_root=root, docker_metadata=docker_metadata, generated_at=generated)
    security = generate_release_security(project_root=root, docker_smoke=docker_smoke, generated_at=generated)

    (bundle / "release_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (bundle / "release_sbom.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (bundle / "release_security.json").write_text(json.dumps(security, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (bundle / "README.md").write_text(render_release_readme(manifest, security), encoding="utf-8")
    return {
        "schema_version": RELEASE_SCHEMA_VERSION,
        "bundle_dir": str(bundle),
        "release_manifest": str(bundle / "release_manifest.json"),
        "release_sbom": str(bundle / "release_sbom.json"),
        "release_security": str(bundle / "release_security.json"),
        "decision": manifest["decision"],
    }


def build_release_manifest(
    *,
    config: AppConfig,
    config_path: str,
    db_path: str,
    bundle_dir: str,
    evidence_package: str,
    checks: dict[str, Any],
    image_tag: str | None,
    image_id: str | None,
    docker_smoke: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    decision = _release_decision(checks)
    manifest = {
        "schema_version": RELEASE_SCHEMA_VERSION,
        "generated_at": generated,
        "release_type": "pilot_release_candidate",
        "decision": decision,
        "amby_version": __version__,
        "source": {
            "git_sha": _git_output(["git", "rev-parse", "HEAD"]),
            "git_branch": _git_output(["git", "branch", "--show-current"]),
            "git_dirty": bool(_git_output(["git", "status", "--short"])),
        },
        "config": {
            "path": config_path,
            "deployment_mode": config.deployment.mode,
            "config_hash": config_hash(config),
            "policy_hash": policy_hash(config),
        },
        "artifacts": {
            "bundle_dir": bundle_dir,
            "audit_db": db_path,
            "evidence_package": evidence_package,
            "release_manifest": "release_manifest.json",
            "release_sbom": "release_sbom.json",
            "release_security": "release_security.json",
            "docker_smoke": "docker-smoke.json",
            "control_policy_bundle": "control-policy-bundle.json",
            "control_heartbeat": "control-heartbeat.json",
            "control_drift": "control-drift.json",
        },
        "image": {
            "tag": image_tag,
            "id": image_id,
        },
        "checks": checks,
        "docker_smoke": _docker_smoke_summary(docker_smoke),
        "privacy": {
            "stores_raw_secrets": False,
            "stores_raw_prompts": False,
            "stores_raw_model_outputs": False,
        },
    }
    manifest["release_manifest_hash"] = hashlib.sha256(_canonical_json(manifest).encode("utf-8")).hexdigest()
    return manifest


def collect_release_checks(bundle_dir: Path, *, docker_smoke: dict[str, Any]) -> dict[str, Any]:
    predeploy = _read_json_file(bundle_dir / "predeploy-result.json")
    evidence_verify = _read_json_file(bundle_dir / "evidence-verify.json")
    control_drift = _read_json_file(bundle_dir / "control-drift.json")
    diagnostics = _read_json_file(bundle_dir / "diagnostics.json")
    test_output = (bundle_dir / "test-output.txt").read_text(encoding="utf-8") if (bundle_dir / "test-output.txt").exists() else ""
    return {
        "tests": {
            "decision": "skip" if "skipping" in test_output.lower() else ("pass" if "passed" in test_output.lower() else "unknown"),
        },
        "predeploy": {
            "decision": predeploy.get("decision", "unknown"),
            "run_id": predeploy.get("run_id"),
        },
        "control_plane_drift": {
            "decision": "pass" if control_drift.get("status") == "clean" else "warn",
            "status": control_drift.get("status"),
            "drift": control_drift.get("drift"),
        },
        "evidence_verify": {
            "decision": "pass" if evidence_verify.get("valid") is True else "fail",
            "valid": evidence_verify.get("valid"),
        },
        "diagnostics": {
            "decision": "pass" if diagnostics.get("status") == "ok" and diagnostics.get("deployment", {}).get("production_ready") is True else "fail",
            "status": diagnostics.get("status"),
            "production_ready": diagnostics.get("deployment", {}).get("production_ready"),
        },
        "docker_smoke": {
            "decision": docker_smoke.get("decision", "skip"),
            "status": docker_smoke.get("status", "skipped"),
        },
    }


def generate_release_sbom(
    *,
    project_root: Path,
    docker_metadata: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    pyproject = _read_toml(project_root / "pyproject.toml")
    uv_lock = _read_toml(project_root / "uv.lock")
    package_json = _read_json_file(project_root / "package.json")
    package_lock = _read_json_file(project_root / "package-lock.json")
    dockerfile = (project_root / "Dockerfile").read_text(encoding="utf-8") if (project_root / "Dockerfile").exists() else ""
    python_project = pyproject.get("project", {}) if isinstance(pyproject.get("project"), dict) else {}
    optional_dependencies = python_project.get("optional-dependencies", {})
    python_packages = [
        {"name": package.get("name"), "version": package.get("version")}
        for package in uv_lock.get("package", [])
        if isinstance(package, dict)
    ]
    node_dependencies = _node_dependencies(package_json, package_lock)
    docker = {
        "base_image": _first_docker_from(dockerfile),
        "has_healthcheck": "HEALTHCHECK" in dockerfile,
        "non_root_user": _docker_user(dockerfile),
        **(docker_metadata or {}),
    }
    return {
        "schema_version": "amby.release_sbom.v1",
        "generated_at": generated,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "python": {
            "project_name": python_project.get("name"),
            "project_version": python_project.get("version"),
            "dependencies": list(python_project.get("dependencies", [])),
            "optional_dependency_groups": sorted(optional_dependencies) if isinstance(optional_dependencies, dict) else [],
            "locked_packages": python_packages,
        },
        "node": {
            "package_name": package_json.get("name"),
            "package_version": package_json.get("version"),
            "engines": package_json.get("engines", {}),
            "dependencies": node_dependencies,
        },
        "docker": docker,
        "lockfiles": {
            "pyproject.toml": _file_summary(project_root / "pyproject.toml"),
            "uv.lock": _file_summary(project_root / "uv.lock"),
            "package.json": _file_summary(project_root / "package.json"),
            "package-lock.json": _file_summary(project_root / "package-lock.json"),
            "Dockerfile": _file_summary(project_root / "Dockerfile"),
        },
        "counts": {
            "python_dependencies": len(python_project.get("dependencies", [])),
            "python_locked_packages": len(python_packages),
            "node_dependencies": len(node_dependencies),
        },
        "privacy": {
            "stores_raw_secrets": False,
            "stores_raw_prompts": False,
            "stores_raw_model_outputs": False,
        },
    }


def generate_release_security(
    *,
    project_root: Path,
    docker_smoke: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    dockerfile = (project_root / "Dockerfile").read_text(encoding="utf-8") if (project_root / "Dockerfile").exists() else ""
    checks = [
        _security_check("python_lockfile", (project_root / "uv.lock").exists(), "uv.lock is present.", fail_when_missing=True),
        _security_check("node_lockfile", (project_root / "package-lock.json").exists(), "package-lock.json is present.", fail_when_missing=True),
        _security_check("dockerfile_present", bool(dockerfile), "Dockerfile is present.", fail_when_missing=True),
        _security_check("docker_non_root_user", bool(_docker_user(dockerfile)), "Dockerfile declares a non-root USER.", fail_when_missing=True),
        _security_check("docker_healthcheck", "HEALTHCHECK" in dockerfile, "Dockerfile declares a healthcheck.", fail_when_missing=True),
        {
            "name": "online_vulnerability_scan",
            "decision": "warn",
            "detail": "No online vulnerability scanner output was provided; pilot RC treats this as warn.",
        },
    ]
    if docker_smoke:
        smoke_decision = str(docker_smoke.get("decision", "skip"))
        checks.append(
            {
                "name": "docker_production_smoke",
                "decision": smoke_decision if smoke_decision in {"pass", "fail", "warn", "skip"} else "warn",
                "detail": str(docker_smoke.get("status") or "docker smoke result recorded"),
            }
        )
    decision = _security_decision(checks)
    return {
        "schema_version": "amby.release_security.v1",
        "generated_at": generated,
        "decision": decision,
        "checks": checks,
        "policy": {
            "pilot_missing_online_scanner_is_warn": True,
            "high_or_critical_findings_fail_when_scanner_output_present": True,
        },
        "privacy": {
            "stores_raw_secrets": False,
        },
    }


def evaluate_docker_smoke(
    *,
    healthz: dict[str, Any] | None,
    diagnostics: dict[str, Any] | None,
    image_tag: str | None = None,
    image_id: str | None = None,
    container_id: str | None = None,
    raw_secret_values: list[str] | None = None,
) -> dict[str, Any]:
    diagnostics = diagnostics or {}
    healthz = healthz or {}
    serialized = json.dumps({"healthz": healthz, "diagnostics": diagnostics}, sort_keys=True)
    raw_secret_present = any(secret and secret in serialized for secret in (raw_secret_values or []))
    production_ready = diagnostics.get("deployment", {}).get("production_ready") is True
    status_ok = diagnostics.get("status") == "ok"
    health_ok = healthz.get("status") == "ok"
    decision = "pass" if health_ok and status_ok and production_ready and not raw_secret_present else "fail"
    return {
        "schema_version": "amby.docker_smoke.v1",
        "decision": decision,
        "status": "ok" if decision == "pass" else "failed",
        "image_tag": image_tag,
        "image_id": image_id,
        "container_id": container_id,
        "healthz": healthz,
        "diagnostics": {
            "status": diagnostics.get("status"),
            "deployment": diagnostics.get("deployment"),
            "config_hash": diagnostics.get("config_hash"),
            "policy_hash": diagnostics.get("policy_hash"),
        },
        "raw_secret_values_present": raw_secret_present,
    }


def render_release_readme(manifest: dict[str, Any], security: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Amby Release Candidate Bundle",
            "",
            f"- Generated at: `{manifest['generated_at']}`",
            f"- Decision: `{manifest['decision']}`",
            f"- Amby version: `{manifest['amby_version']}`",
            f"- Git SHA: `{manifest['source'].get('git_sha') or 'unknown'}`",
            f"- Config hash: `{manifest['config']['config_hash']}`",
            f"- Policy hash: `{manifest['config']['policy_hash']}`",
            f"- Evidence package: `{manifest['artifacts']['evidence_package']}`",
            f"- Image tag: `{manifest['image'].get('tag') or 'not built'}`",
            f"- Security decision: `{security['decision']}`",
            "",
            "## Files",
            "",
            "- `release_manifest.json`: release decision, hashes, source revision, artifact pointers, and gate results.",
            "- `release_sbom.json`: offline Python, Node, lockfile, and Docker metadata.",
            "- `release_security.json`: release-candidate security checks and scanner status.",
            "- `docker-smoke.json`: Docker production smoke result, or skipped status.",
            "- `control-policy-bundle.json`: signed expected policy bundle.",
            "- `control-heartbeat.json`: metadata-only heartbeat.",
            "- `control-drift.json`: expected-vs-running policy drift result.",
            "- `evidence/`: full evidence package directory.",
            "",
            "This is pilot release-candidate evidence. It is not external WORM/notarized production evidence.",
            "",
        ]
    )


def _release_decision(checks: dict[str, Any]) -> str:
    decisions = [str(item.get("decision", "unknown")) for item in checks.values() if isinstance(item, dict)]
    if any(decision == "fail" for decision in decisions):
        return "fail"
    if any(decision in {"warn", "unknown", "skip"} for decision in decisions):
        return "warn"
    return "pass"


def _security_decision(checks: list[dict[str, Any]]) -> str:
    decisions = [str(check.get("decision", "warn")) for check in checks]
    if "fail" in decisions:
        return "fail"
    if "warn" in decisions or "skip" in decisions:
        return "warn"
    return "pass"


def _security_check(name: str, ok: bool, detail: str, *, fail_when_missing: bool) -> dict[str, str]:
    return {
        "name": name,
        "decision": "pass" if ok else ("fail" if fail_when_missing else "warn"),
        "detail": detail,
    }


def _docker_smoke_summary(docker_smoke: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision": docker_smoke.get("decision"),
        "status": docker_smoke.get("status"),
        "image_tag": docker_smoke.get("image_tag"),
        "image_id": docker_smoke.get("image_id"),
        "raw_secret_values_present": docker_smoke.get("raw_secret_values_present"),
    }


def _default_docker_smoke() -> dict[str, Any]:
    return {
        "schema_version": "amby.docker_smoke.v1",
        "decision": "skip",
        "status": "skipped",
        "reason": "RUN_DOCKER=0 or Docker unavailable.",
    }


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _node_dependencies(package_json: dict[str, Any], package_lock: dict[str, Any]) -> list[dict[str, Any]]:
    dependencies: dict[str, dict[str, Any]] = {}
    for field in ("dependencies", "devDependencies"):
        for name, spec in (package_json.get(field) or {}).items():
            dependencies[str(name)] = {"name": str(name), "specifier": str(spec), "scope": field}
    packages = package_lock.get("packages") or {}
    if isinstance(packages, dict):
        for path, metadata in packages.items():
            if not path.startswith("node_modules/") or not isinstance(metadata, dict):
                continue
            name = path.removeprefix("node_modules/")
            item = dependencies.setdefault(name, {"name": name, "scope": "locked"})
            if metadata.get("version"):
                item["version"] = str(metadata["version"])
    return sorted(dependencies.values(), key=lambda item: str(item["name"]))


def _file_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"present": False, "sha256": None}
    return {"present": True, "sha256": _sha256_file(path)}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_docker_from(dockerfile: str) -> str | None:
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            return stripped.split(maxsplit=1)[1]
    return None


def _docker_user(dockerfile: str) -> str | None:
    for line in reversed(dockerfile.splitlines()):
        stripped = line.strip()
        if stripped.upper().startswith("USER "):
            user = stripped.split(maxsplit=1)[1]
            return None if user in {"0", "root"} else user
    return None


def _git_output(args: list[str]) -> str | None:
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True)
    except OSError:
        return None
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output or None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
