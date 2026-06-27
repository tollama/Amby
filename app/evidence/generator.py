from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app import __version__
from app.audit.store import AuditStore
from app.config import load_config


@dataclass(frozen=True)
class EvidenceOptions:
    db_path: str
    config_path: str = "config.yaml"
    output_root: str = "evidence"
    start: str | None = None
    end: str | None = None
    generated_at: str | None = None
    package_name: str | None = None


def generate_evidence_package(options: EvidenceOptions) -> dict[str, Any]:
    generated_at = options.generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    package_name = options.package_name or generated_at
    package_dir = _create_package_dir(Path(options.output_root).expanduser(), package_name)

    store = AuditStore(options.db_path)
    store.initialize()
    events = store.export_events(start=options.start, end=options.end)
    event_chain = _build_event_chain(events)
    stats = _stats(events)

    _write_jsonl(package_dir / "audit_events.jsonl", events)
    (package_dir / "audit_events.csv").write_text(store.to_csv(events), encoding="utf-8")
    _write_jsonl(package_dir / "audit_chain.jsonl", event_chain)
    _write_config_snapshot(package_dir / "config_snapshot.yaml", options.config_path)
    (package_dir / "report.md").write_text(
        _render_report(
            generated_at=generated_at,
            options=options,
            events=events,
            stats=stats,
            event_chain=event_chain,
        ),
        encoding="utf-8",
    )

    hashes = _hash_package_files(package_dir)
    (package_dir / "hashes.sha256").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())),
        encoding="utf-8",
    )

    manifest = {
        "schema_version": "amby.evidence.v1",
        "generated_at": generated_at,
        "amby_version": __version__,
        "package_dir": str(package_dir),
        "filters": {"from": options.start, "to": options.end},
        "source": {
            "audit_db": options.db_path,
            "config_path": options.config_path,
        },
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "counts": stats,
        "event_chain_head": event_chain[-1]["chain_hash"] if event_chain else None,
        "files": {name: {"sha256": digest} for name, digest in sorted(hashes.items())},
    }
    manifest_bytes = _canonical_json(manifest).encode("utf-8")
    manifest["manifest_hash"] = hashlib.sha256(manifest_bytes).hexdigest()
    (package_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_evidence_package(package_dir: str | Path) -> dict[str, Any]:
    root = Path(package_dir)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    file_results: dict[str, bool] = {}
    for filename, metadata in manifest.get("files", {}).items():
        path = root / filename
        file_results[filename] = path.exists() and _sha256_file(path) == metadata.get("sha256")

    chain_results = _verify_chain(root / "audit_chain.jsonl")
    manifest_without_hash = dict(manifest)
    expected_manifest_hash = manifest_without_hash.pop("manifest_hash", None)
    actual_manifest_hash = hashlib.sha256(_canonical_json(manifest_without_hash).encode("utf-8")).hexdigest()

    valid = all(file_results.values()) and chain_results["valid"] and expected_manifest_hash == actual_manifest_hash
    return {
        "valid": valid,
        "manifest_hash_valid": expected_manifest_hash == actual_manifest_hash,
        "files": file_results,
        "chain": chain_results,
    }


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(_canonical_json(row) + "\n")


def _create_package_dir(output_root: Path, package_name: str) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    candidate = output_root / package_name
    if not candidate.exists():
        candidate.mkdir()
        return candidate

    for index in range(1, 1000):
        candidate = output_root / f"{package_name}-{index:03d}"
        if not candidate.exists():
            candidate.mkdir()
            return candidate

    raise FileExistsError(f"Could not create a unique evidence package directory under {output_root}")


def _write_config_snapshot(path: Path, config_path: str) -> None:
    source = Path(config_path)
    if source.exists():
        path.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        return

    config = load_config(config_path)
    path.write_text(
        "\n".join(
            [
                "# Config file was not found; this is the parsed runtime summary.",
                f"audit_store: {config.audit.store}",
                f"retention_days: {config.audit.retention_days}",
                f"dashboard: {config.server.dashboard}",
                f"port: {config.server.port}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _build_event_chain(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    previous_hash = "0" * 64
    chain: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        event_hash = hashlib.sha256(_canonical_json(event).encode("utf-8")).hexdigest()
        chain_hash = hashlib.sha256(f"{previous_hash}{event_hash}".encode("utf-8")).hexdigest()
        chain.append(
            {
                "index": index,
                "event_id": event["id"],
                "request_id": event["request_id"],
                "event_hash": event_hash,
                "previous_hash": previous_hash,
                "chain_hash": chain_hash,
            }
        )
        previous_hash = chain_hash
    return chain


def _verify_chain(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"valid": False, "event_count": 0, "chain_head": None}

    previous_hash = "0" * 64
    count = 0
    chain_head = None
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            expected = hashlib.sha256(f"{previous_hash}{row['event_hash']}".encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["chain_hash"] != expected:
                return {"valid": False, "event_count": count, "chain_head": chain_head}
            previous_hash = row["chain_hash"]
            chain_head = row["chain_hash"]
            count += 1
    return {"valid": True, "event_count": count, "chain_head": chain_head}


def _stats(events: list[dict[str, Any]]) -> dict[str, Any]:
    decisions = {"allow": 0, "block": 0, "redact": 0, "flag": 0}
    directions = {"input": 0, "output": 0}
    asi_counts: dict[str, int] = {}
    scanner_counts: dict[str, int] = {}

    for event in events:
        decisions[event.get("decision", "allow")] = decisions.get(event.get("decision", "allow"), 0) + 1
        directions[event.get("direction", "input")] = directions.get(event.get("direction", "input"), 0) + 1
        for scanner in event.get("scanners_run", []):
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
        for detection in event.get("detections", []):
            asi_id = str(detection.get("asi_id") or "ASI_UNMAPPED")
            asi_counts[asi_id] = asi_counts.get(asi_id, 0) + 1

    return {
        "events": len(events),
        "decisions": decisions,
        "directions": directions,
        "asi": dict(sorted(asi_counts.items())),
        "scanners_run": dict(sorted(scanner_counts.items())),
    }


def _render_report(
    *,
    generated_at: str,
    options: EvidenceOptions,
    events: list[dict[str, Any]],
    stats: dict[str, Any],
    event_chain: list[dict[str, Any]],
) -> str:
    chain_head = event_chain[-1]["chain_hash"] if event_chain else "none"
    request_ids = sorted({event["request_id"] for event in events})
    lines = [
        "# Amby MVP Evidence Report",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Amby version: `{__version__}`",
        f"- Audit DB: `{options.db_path}`",
        f"- Config snapshot: `config_snapshot.yaml`",
        f"- Filter from: `{options.start or 'beginning'}`",
        f"- Filter to: `{options.end or 'end'}`",
        f"- Event count: `{stats['events']}`",
        f"- Event chain head: `{chain_head}`",
        "",
        "## What This Proves",
        "",
        "- The gateway produced persistent audit events for the selected period.",
        "- Events include scanner decisions, ASI tags, latency, and masked snippets.",
        "- The evidence package includes a hash chain and file hashes to detect tampering after generation.",
        "- The config snapshot records the policy context used for the run.",
        "",
        "## Decision Counts",
        "",
        _markdown_table(["decision", "count"], [[key, value] for key, value in stats["decisions"].items()]),
        "",
        "## ASI Counts",
        "",
        _markdown_table(["asi_id", "count"], [[key, value] for key, value in stats["asi"].items()]) if stats["asi"] else "No ASI detections.",
        "",
        "## Request IDs",
        "",
        "\n".join(f"- `{request_id}`" for request_id in request_ids) if request_ids else "No request IDs.",
        "",
        "## Evidence Files",
        "",
        "- `audit_events.jsonl`: canonical JSONL audit event export",
        "- `audit_events.csv`: CSV audit export",
        "- `audit_chain.jsonl`: event-level tamper-evident hash chain",
        "- `config_snapshot.yaml`: policy/config snapshot",
        "- `hashes.sha256`: file-level SHA-256 checksums",
        "- `manifest.json`: package metadata and manifest hash",
        "",
        "## Known MVP Limits",
        "",
        "- This package proves integrity after evidence generation; full WORM/remote notarization is a later control.",
        "- Streaming output DLP remains a hardening item unless Phase 0.5 has been completed.",
    ]
    return "\n".join(lines) + "\n"


def _markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return "\n".join(lines)


def _hash_package_files(package_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(package_dir.iterdir()):
        if path.is_file() and path.name not in {"manifest.json", "hashes.sha256"}:
            hashes[path.name] = _sha256_file(path)
    return hashes


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
