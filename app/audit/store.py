from __future__ import annotations

import csv
import io
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import Any

from app.audit.sanitize import sanitize_audit_snippet


@dataclass(frozen=True)
class AuditEventInput:
    request_id: str
    direction: str
    upstream_model: str
    scanners_run: list[str]
    detections: list[dict[str, object]]
    decision: str
    latency_ms: int
    error: str | None
    client_meta: dict[str, object]


@dataclass(frozen=True)
class ToolCallEventInput:
    request_id: str
    agent_id: str
    session_id: str | None
    tool_name: str
    action: str
    method: str
    target_host: str | None
    target: str | None
    decision: str
    risk_level: str
    approval_id: str | None
    latency_ms: int
    detections: list[dict[str, object]]
    reasons: list[str]
    policy_snapshot: dict[str, object]
    client_meta: dict[str, object]


class AuditStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        if self.db_path != ":memory:":
            Path(self.db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_schema_sql())
            _sanitize_existing_snippets(conn)

    def record_event(self, event: AuditEventInput) -> dict[str, Any]:
        row = {
            "id": str(uuid.uuid4()),
            "ts": datetime.now(UTC).isoformat(),
            "request_id": event.request_id,
            "direction": event.direction,
            "upstream_model": event.upstream_model,
            "scanners_run": json.dumps(event.scanners_run, separators=(",", ":")),
            "detections": json.dumps(event.detections, separators=(",", ":")),
            "decision": event.decision,
            "latency_ms": int(event.latency_ms),
            "error": event.error,
            "client_meta": json.dumps(event.client_meta, separators=(",", ":")),
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                  id, ts, request_id, direction, upstream_model, scanners_run, detections,
                  decision, latency_ms, error, client_meta
                ) VALUES (
                  :id, :ts, :request_id, :direction, :upstream_model, :scanners_run,
                  :detections, :decision, :latency_ms, :error, :client_meta
                )
                """,
                row,
            )
        return _decode_row(row)

    def record_tool_call_event(self, event: ToolCallEventInput) -> dict[str, Any]:
        row = {
            "id": str(uuid.uuid4()),
            "ts": datetime.now(UTC).isoformat(),
            "request_id": event.request_id,
            "agent_id": event.agent_id,
            "session_id": event.session_id,
            "tool_name": event.tool_name,
            "action": event.action,
            "method": event.method,
            "target_host": event.target_host,
            "target": event.target,
            "decision": event.decision,
            "risk_level": event.risk_level,
            "approval_id": event.approval_id,
            "latency_ms": int(event.latency_ms),
            "detections": json.dumps(event.detections, separators=(",", ":")),
            "reasons": json.dumps(event.reasons, separators=(",", ":")),
            "policy_snapshot": json.dumps(event.policy_snapshot, separators=(",", ":")),
            "client_meta": json.dumps(event.client_meta, separators=(",", ":")),
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_call_events (
                  id, ts, request_id, agent_id, session_id, tool_name, action, method,
                  target_host, target, decision, risk_level, approval_id, latency_ms,
                  detections, reasons, policy_snapshot, client_meta
                ) VALUES (
                  :id, :ts, :request_id, :agent_id, :session_id, :tool_name, :action,
                  :method, :target_host, :target, :decision, :risk_level, :approval_id,
                  :latency_ms, :detections, :reasons, :policy_snapshot, :client_meta
                )
                """,
                row,
            )
        return _decode_tool_call_row(row)

    def list_events(
        self,
        *,
        q: str | None = None,
        direction: str | None = None,
        decision: str | None = None,
        limit: int = 100,
        offset: int = 0,
        newest_first: bool = True,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[object] = []
        if q:
            like = f"%{q}%"
            where.append("(request_id LIKE ? OR upstream_model LIKE ? OR detections LIKE ? OR error LIKE ?)")
            params.extend([like, like, like, like])
        if direction:
            where.append("direction = ?")
            params.append(direction)
        if decision:
            where.append("decision = ?")
            params.append(decision)

        sql = "SELECT * FROM audit_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts " + ("DESC" if newest_first else "ASC")
        sql += " LIMIT ? OFFSET ?"
        params.extend([max(1, min(limit, 500)), max(0, offset)])

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_decode_row(dict(row)) for row in rows]

    def export_events(
        self,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[object] = []
        if start:
            where.append("ts >= ?")
            params.append(start)
        if end:
            where.append("ts <= ?")
            params.append(end)

        sql = "SELECT * FROM audit_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts ASC"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_decode_row(dict(row)) for row in rows]

    def list_tool_call_events(
        self,
        *,
        q: str | None = None,
        agent_id: str | None = None,
        decision: str | None = None,
        limit: int = 100,
        offset: int = 0,
        newest_first: bool = True,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[object] = []
        if q:
            like = f"%{q}%"
            where.append("(request_id LIKE ? OR agent_id LIKE ? OR tool_name LIKE ? OR action LIKE ? OR target_host LIKE ?)")
            params.extend([like, like, like, like, like])
        if agent_id:
            where.append("agent_id = ?")
            params.append(agent_id)
        if decision:
            where.append("decision = ?")
            params.append(decision)

        sql = "SELECT * FROM tool_call_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts " + ("DESC" if newest_first else "ASC")
        sql += " LIMIT ? OFFSET ?"
        params.extend([max(1, min(limit, 500)), max(0, offset)])

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_decode_tool_call_row(dict(row)) for row in rows]

    def export_tool_call_events(
        self,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[object] = []
        if start:
            where.append("ts >= ?")
            params.append(start)
        if end:
            where.append("ts <= ?")
            params.append(end)

        sql = "SELECT * FROM tool_call_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts ASC"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_decode_tool_call_row(dict(row)) for row in rows]

    def create_tool_approval(
        self,
        *,
        request_id: str,
        agent_id: str,
        tool_name: str,
        action: str,
        method: str,
        target_host: str | None,
        risk_level: str,
        reason: str,
        payload: dict[str, object],
        ttl_seconds: int,
    ) -> dict[str, Any]:
        created_at = datetime.now(UTC)
        row = {
            "id": str(uuid.uuid4()),
            "created_at": created_at.isoformat(),
            "expires_at": (created_at + timedelta(seconds=ttl_seconds)).isoformat(),
            "decided_at": None,
            "status": "pending",
            "request_id": request_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "action": action,
            "method": method,
            "target_host": target_host,
            "risk_level": risk_level,
            "reason": reason,
            "approver": None,
            "comment": None,
            "payload": json.dumps(payload, separators=(",", ":")),
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_approvals (
                  id, created_at, expires_at, decided_at, status, request_id, agent_id,
                  tool_name, action, method, target_host, risk_level, reason, approver,
                  comment, payload
                ) VALUES (
                  :id, :created_at, :expires_at, :decided_at, :status, :request_id,
                  :agent_id, :tool_name, :action, :method, :target_host, :risk_level,
                  :reason, :approver, :comment, :payload
                )
                """,
                row,
            )
        return _decode_approval_row(row)

    def get_tool_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tool_approvals WHERE id = ?", (approval_id,)).fetchone()
            if row is None:
                return None
            decoded = _decode_approval_row(dict(row))
            if decoded["status"] == "pending" and _is_expired(str(decoded["expires_at"])):
                conn.execute(
                    "UPDATE tool_approvals SET status = ?, decided_at = ? WHERE id = ?",
                    ("expired", datetime.now(UTC).isoformat(), approval_id),
                )
                row = conn.execute("SELECT * FROM tool_approvals WHERE id = ?", (approval_id,)).fetchone()
                if row is None:
                    return None
                decoded = _decode_approval_row(dict(row))
        return decoded

    def decide_tool_approval(self, approval_id: str, *, status: str, approver: str, comment: str | None = None) -> dict[str, Any] | None:
        if status not in {"approved", "denied"}:
            raise ValueError(f"Invalid approval decision status={status!r}")
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tool_approvals WHERE id = ?", (approval_id,)).fetchone()
            if row is None:
                return None
            decoded = _decode_approval_row(dict(row))
            if decoded["status"] == "pending" and _is_expired(str(decoded["expires_at"])):
                conn.execute(
                    "UPDATE tool_approvals SET status = ?, decided_at = ? WHERE id = ?",
                    ("expired", datetime.now(UTC).isoformat(), approval_id),
                )
                row = conn.execute("SELECT * FROM tool_approvals WHERE id = ?", (approval_id,)).fetchone()
                return _decode_approval_row(dict(row)) if row is not None else None
            if decoded["status"] != "pending":
                return decoded
            conn.execute(
                """
                UPDATE tool_approvals
                SET status = ?, decided_at = ?, approver = ?, comment = ?
                WHERE id = ?
                """,
                (status, datetime.now(UTC).isoformat(), approver, comment, approval_id),
            )
        return self.get_tool_approval(approval_id)

    def stats_by_asi(self) -> list[dict[str, Any]]:
        counts: dict[str, dict[str, Any]] = {}
        with self._connect() as conn:
            rows = conn.execute("SELECT detections FROM audit_events").fetchall()
            tool_rows = conn.execute("SELECT detections FROM tool_call_events").fetchall()

        for row in [*rows, *tool_rows]:
            for detection in json.loads(row["detections"] or "[]"):
                asi_id = detection.get("asi_id") or "ASI_UNMAPPED"
                item = counts.setdefault(str(asi_id), {"asi_id": str(asi_id), "count": 0, "severity": detection.get("severity")})
                item["count"] += 1
        return sorted(counts.values(), key=lambda item: (-int(item["count"]), str(item["asi_id"])))

    def to_csv(self, rows: list[dict[str, Any]]) -> str:
        output = io.StringIO()
        fields = [
            "id",
            "ts",
            "request_id",
            "direction",
            "upstream_model",
            "scanners_run",
            "detections",
            "decision",
            "latency_ms",
            "error",
            "client_meta",
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    **row,
                    "scanners_run": json.dumps(row["scanners_run"], separators=(",", ":")),
                    "detections": json.dumps(row["detections"], separators=(",", ":")),
                    "client_meta": json.dumps(row["client_meta"], separators=(",", ":")),
                }
            )
        return output.getvalue()

    def tool_calls_to_csv(self, rows: list[dict[str, Any]]) -> str:
        output = io.StringIO()
        fields = [
            "id",
            "ts",
            "request_id",
            "agent_id",
            "session_id",
            "tool_name",
            "action",
            "method",
            "target_host",
            "target",
            "decision",
            "risk_level",
            "approval_id",
            "latency_ms",
            "detections",
            "reasons",
            "policy_snapshot",
            "client_meta",
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            csv_row = {field: row.get(field) for field in fields}
            csv_row["detections"] = json.dumps(row["detections"], separators=(",", ":"))
            csv_row["reasons"] = json.dumps(row["reasons"], separators=(",", ":"))
            csv_row["policy_snapshot"] = json.dumps(row["policy_snapshot"], separators=(",", ":"))
            csv_row["client_meta"] = json.dumps(row["client_meta"], separators=(",", ":"))
            writer.writerow(csv_row)
        return output.getvalue()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn


def _decode_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["scanners_run"] = json.loads(decoded.get("scanners_run") or "[]")
    decoded["detections"] = json.loads(decoded.get("detections") or "[]")
    decoded["client_meta"] = json.loads(decoded.get("client_meta") or "{}")
    return decoded


def _decode_tool_call_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["detections"] = json.loads(decoded.get("detections") or "[]")
    decoded["reasons"] = json.loads(decoded.get("reasons") or "[]")
    decoded["policy_snapshot"] = json.loads(decoded.get("policy_snapshot") or "{}")
    decoded["client_meta"] = json.loads(decoded.get("client_meta") or "{}")
    decoded["direction"] = "tool_call"
    decoded["upstream_model"] = decoded.get("tool_name")
    decoded["scanners_run"] = [detection.get("control") or detection.get("scanner") for detection in decoded["detections"]]
    decoded["error"] = None
    return decoded


def _decode_approval_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["payload"] = json.loads(decoded.get("payload") or "{}")
    return decoded


def _is_expired(expires_at: str) -> bool:
    try:
        parsed = datetime.fromisoformat(expires_at)
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed <= datetime.now(UTC)


def _schema_sql() -> str:
    return resources.files("app.audit").joinpath("schema.sql").read_text(encoding="utf-8")


def _sanitize_existing_snippets(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT id, detections FROM audit_events").fetchall()
    for row in rows:
        detections = json.loads(row["detections"] or "[]")
        changed = False
        for detection in detections:
            snippet = detection.get("snippet_masked")
            if isinstance(snippet, str):
                sanitized = sanitize_audit_snippet(snippet)
                if sanitized != snippet:
                    detection["snippet_masked"] = sanitized
                    changed = True
        if changed:
            conn.execute(
                "UPDATE audit_events SET detections = ? WHERE id = ?",
                (json.dumps(detections, separators=(",", ":")), row["id"]),
            )
