from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app import __version__
from app.audit.store import AuditStore
from app.config import load_config
from app.framework_adapters.discovery import discover_runtime_inventory
from app.mythos.coverage import build_mythos_readiness


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
    tool_events = store.export_tool_call_events(start=options.start, end=options.end)
    context_events = store.export_context_events(start=options.start, end=options.end)
    event_chain = _build_event_chain(events)
    tool_event_chain = _build_event_chain(tool_events)
    context_event_chain = _build_event_chain(context_events)
    config = load_config(options.config_path)
    discovered_inventory = discover_runtime_inventory(config.framework_adapters, workspace_root=Path.cwd())
    stats = build_evidence_stats(events, tool_events, context_events)
    stats["tool_inventory"] = len(config.agent_firewall.inventory)
    stats["discovered_inventory"] = len(discovered_inventory.get("items", []))
    mythos_readiness = build_mythos_readiness(stats)

    _write_jsonl(package_dir / "audit_events.jsonl", events)
    (package_dir / "audit_events.csv").write_text(store.to_csv(events), encoding="utf-8")
    _write_jsonl(package_dir / "audit_chain.jsonl", event_chain)
    _write_jsonl(package_dir / "tool_call_events.jsonl", tool_events)
    (package_dir / "tool_call_events.csv").write_text(store.tool_calls_to_csv(tool_events), encoding="utf-8")
    _write_jsonl(package_dir / "tool_call_chain.jsonl", tool_event_chain)
    _write_jsonl(package_dir / "context_events.jsonl", context_events)
    (package_dir / "context_events.csv").write_text(store.context_events_to_csv(context_events), encoding="utf-8")
    _write_jsonl(package_dir / "context_chain.jsonl", context_event_chain)
    (package_dir / "discovered_inventory.json").write_text(
        json.dumps(discovered_inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_config_snapshot(package_dir / "config_snapshot.yaml", options.config_path)
    (package_dir / "mythos_ready.json").write_text(
        json.dumps(mythos_readiness, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (package_dir / "report.md").write_text(
        _render_report(
            generated_at=generated_at,
            options=options,
            events=events,
            stats=stats,
            event_chain=event_chain,
            tool_event_chain=tool_event_chain,
            context_event_chain=context_event_chain,
            mythos_readiness=mythos_readiness,
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
        "mythos_readiness": {
            "schema_version": mythos_readiness["schema_version"],
            "source": mythos_readiness["source"],
            "status_counts": mythos_readiness["status_counts"],
            "evidence_counts": mythos_readiness["evidence_counts"],
        },
        "event_chain_head": event_chain[-1]["chain_hash"] if event_chain else None,
        "tool_call_chain_head": tool_event_chain[-1]["chain_hash"] if tool_event_chain else None,
        "context_chain_head": context_event_chain[-1]["chain_hash"] if context_event_chain else None,
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
    tool_chain_results = _verify_optional_chain(root, manifest, "tool_call_chain.jsonl")
    context_chain_results = _verify_optional_chain(root, manifest, "context_chain.jsonl")
    manifest_without_hash = dict(manifest)
    expected_manifest_hash = manifest_without_hash.pop("manifest_hash", None)
    actual_manifest_hash = hashlib.sha256(_canonical_json(manifest_without_hash).encode("utf-8")).hexdigest()

    valid = (
        all(file_results.values())
        and chain_results["valid"]
        and tool_chain_results["valid"]
        and context_chain_results["valid"]
        and expected_manifest_hash == actual_manifest_hash
    )
    return {
        "valid": valid,
        "manifest_hash_valid": expected_manifest_hash == actual_manifest_hash,
        "files": file_results,
        "chain": chain_results,
        "tool_call_chain": tool_chain_results,
        "context_chain": context_chain_results,
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


def _verify_optional_chain(root: Path, manifest: dict[str, Any], filename: str) -> dict[str, Any]:
    if filename not in manifest.get("files", {}):
        return {"valid": True, "event_count": 0, "chain_head": None, "present": False}
    result = _verify_chain(root / filename)
    result["present"] = True
    return result


def build_evidence_stats(
    events: list[dict[str, Any]],
    tool_events: list[dict[str, Any]] | None = None,
    context_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    tool_events = tool_events or []
    context_events = context_events or []
    decisions = {"allow": 0, "block": 0, "redact": 0, "flag": 0}
    directions = {"input": 0, "output": 0}
    tool_decisions = {"allow": 0, "block": 0, "approval_required": 0}
    context_decisions = {"allow": 0, "block": 0, "redact": 0, "flag": 0}
    context_hooks: dict[str, int] = {}
    asi_counts: dict[str, int] = {}
    framework_counts: dict[str, dict[str, int]] = {"owasp_llm": {}, "owasp_asi": {}, "nist_rmf": {}, "nist_genai": {}}
    scanner_counts: dict[str, int] = {}

    for event in events:
        decisions[event.get("decision", "allow")] = decisions.get(event.get("decision", "allow"), 0) + 1
        directions[event.get("direction", "input")] = directions.get(event.get("direction", "input"), 0) + 1
        for scanner in event.get("scanners_run", []):
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
        for detection in event.get("detections", []):
            asi_id = str(detection.get("asi_id") or "ASI_UNMAPPED")
            asi_counts[asi_id] = asi_counts.get(asi_id, 0) + 1
            for key in framework_counts:
                values = detection.get(key) or []
                if isinstance(values, str):
                    values = [values]
                for value in values:
                    value_str = str(value)
                    framework_counts[key][value_str] = framework_counts[key].get(value_str, 0) + 1

    for event in tool_events:
        decision = str(event.get("decision", "allow"))
        tool_decisions[decision] = tool_decisions.get(decision, 0) + 1
        for detection in event.get("detections", []):
            asi_id = str(detection.get("asi_id") or "ASI_UNMAPPED")
            asi_counts[asi_id] = asi_counts.get(asi_id, 0) + 1
            scanner = str(detection.get("control") or detection.get("scanner") or "tool_firewall")
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
            for key in framework_counts:
                values = detection.get(key) or []
                if isinstance(values, str):
                    values = [values]
                for value in values:
                    value_str = str(value)
                    framework_counts[key][value_str] = framework_counts[key].get(value_str, 0) + 1

    for event in context_events:
        decision = str(event.get("decision", "allow"))
        context_decisions[decision] = context_decisions.get(decision, 0) + 1
        hook_type = str(event.get("hook_type") or "unknown")
        context_hooks[hook_type] = context_hooks.get(hook_type, 0) + 1
        for scanner in event.get("scanners_run", []):
            scanner_counts[str(scanner)] = scanner_counts.get(str(scanner), 0) + 1
        for detection in event.get("detections", []):
            asi_id = str(detection.get("asi_id") or "ASI_UNMAPPED")
            asi_counts[asi_id] = asi_counts.get(asi_id, 0) + 1
            scanner = str(detection.get("control") or detection.get("scanner") or "context_hook")
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
            for key in framework_counts:
                values = detection.get(key) or []
                if isinstance(values, str):
                    values = [values]
                for value in values:
                    value_str = str(value)
                    framework_counts[key][value_str] = framework_counts[key].get(value_str, 0) + 1

    return {
        "events": len(events),
        "tool_calls": len(tool_events),
        "context_events": len(context_events),
        "tool_inventory": 0,
        "discovered_inventory": 0,
        "decisions": decisions,
        "tool_decisions": tool_decisions,
        "context_decisions": context_decisions,
        "context_hooks": dict(sorted(context_hooks.items())),
        "directions": directions,
        "asi": dict(sorted(asi_counts.items())),
        "frameworks": {key: dict(sorted(value.items())) for key, value in framework_counts.items()},
        "scanners_run": dict(sorted(scanner_counts.items())),
    }


def _render_report(
    *,
    generated_at: str,
    options: EvidenceOptions,
    events: list[dict[str, Any]],
    stats: dict[str, Any],
    event_chain: list[dict[str, Any]],
    tool_event_chain: list[dict[str, Any]],
    context_event_chain: list[dict[str, Any]],
    mythos_readiness: dict[str, Any],
) -> str:
    chain_head = event_chain[-1]["chain_hash"] if event_chain else "none"
    tool_chain_head = tool_event_chain[-1]["chain_hash"] if tool_event_chain else "none"
    context_chain_head = context_event_chain[-1]["chain_hash"] if context_event_chain else "none"
    request_ids = sorted({event["request_id"] for event in events})
    implemented_controls = [
        control
        for control in mythos_readiness["controls"]
        if control["status"] == "implemented"
    ]
    partial_controls = [
        control
        for control in mythos_readiness["controls"]
        if control["status"] == "partial"
    ]
    planned_controls = [
        control
        for control in mythos_readiness["controls"]
        if control["status"] == "planned"
    ]
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
        f"- Tool-call count: `{stats['tool_calls']}`",
        f"- Context hook count: `{stats['context_events']}`",
        f"- Discovered inventory count: `{stats.get('discovered_inventory', 0)}`",
        f"- Event chain head: `{chain_head}`",
        f"- Tool-call chain head: `{tool_chain_head}`",
        f"- Context chain head: `{context_chain_head}`",
        "",
        "## What This Proves",
        "",
        "- The gateway produced persistent audit events for the selected period.",
        "- Events include scanner decisions, ASI tags, latency, and masked snippets.",
        "- The evidence package includes a hash chain and file hashes to detect tampering after generation.",
        "- Tool-call evidence separates AI proposal, policy decision, human approval, and final authorization.",
        "- Context hook evidence records framework memory/RAG decisions without storing raw memory or retrieved text.",
        "- Discovered inventory captures local MCP/plugin/skill exposure without storing secret values.",
        "- The config snapshot records the policy context used for the run.",
        "- The Mythos-ready section distinguishes implemented, partial, and planned controls instead of claiming full coverage.",
        "",
        "## Decision Counts",
        "",
        _markdown_table(["decision", "count"], [[key, value] for key, value in stats["decisions"].items()]),
        "",
        "## Tool-call Decision Counts",
        "",
        _markdown_table(["decision", "count"], [[key, value] for key, value in stats["tool_decisions"].items()]),
        "",
        "## Context Hook Decision Counts",
        "",
        _markdown_table(["decision", "count"], [[key, value] for key, value in stats["context_decisions"].items()]),
        "",
        "## ASI Counts",
        "",
        _markdown_table(["asi_id", "count"], [[key, value] for key, value in stats["asi"].items()]) if stats["asi"] else "No ASI detections.",
        "",
        "## Framework Counts",
        "",
        _framework_counts_table(stats),
        "",
        "## Mythos-ready Coverage",
        "",
        f"- Source: {mythos_readiness['source']['title']}",
        f"- Source URL: {mythos_readiness['source']['source_url']}",
        f"- Last updated: `{mythos_readiness['source']['last_updated']}`",
        f"- Status counts: `{json.dumps(mythos_readiness['status_counts'], sort_keys=True)}`",
        f"- Evidence presence: `{json.dumps(mythos_readiness['evidence_counts'], sort_keys=True)}`",
        "",
        "### Implemented Controls",
        "",
        _control_table(implemented_controls),
        "",
        "### Partial Controls",
        "",
        _control_table(partial_controls),
        "",
        "### Planned Controls",
        "",
        _control_table(planned_controls),
        "",
        "Interpretation: Amby MVP is a Mythos-ready evidence and model-boundary control seed, not a complete Mythos-ready security program.",
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
        "- `tool_call_events.jsonl`: canonical JSONL agent firewall event export",
        "- `tool_call_events.csv`: CSV agent firewall export",
        "- `tool_call_chain.jsonl`: tool-call tamper-evident hash chain",
        "- `context_events.jsonl`: canonical JSONL framework memory/RAG hook export",
        "- `context_events.csv`: CSV framework hook export",
        "- `context_chain.jsonl`: context hook tamper-evident hash chain",
        "- `discovered_inventory.json`: MCP/plugin/skill discovery snapshot",
        "- `config_snapshot.yaml`: policy/config snapshot",
        "- `mythos_ready.json`: CSA Mythos-ready control coverage and evidence matrix",
        "- `hashes.sha256`: file-level SHA-256 checksums",
        "- `manifest.json`: package metadata and manifest hash",
        "",
        "## Known MVP Limits",
        "",
        "- This package proves integrity after evidence generation; full WORM/remote notarization is a later control.",
        "- Streaming output DLP uses Phase 0.5 buffer-then-scan mode; true token-by-token inline DLP is a later control.",
    ]
    return "\n".join(lines) + "\n"


def _control_table(controls: list[dict[str, Any]]) -> str:
    if not controls:
        return "No controls in this category."
    rows = [
        [
            control["control_id"],
            control["title"],
            control["roadmap_phase"],
            "yes" if control["evidence_present"] else "no",
            control["next_step"],
        ]
        for control in controls
    ]
    return _markdown_table(["control", "title", "phase", "evidence", "next step"], rows)


def _framework_counts_table(stats: dict[str, Any]) -> str:
    rows: list[list[Any]] = []
    for framework, counts in stats.get("frameworks", {}).items():
        for item_id, count in counts.items():
            rows.append([framework, item_id, count])
    if not rows:
        return "No framework detections."
    return _markdown_table(["framework", "id", "count"], rows)


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
