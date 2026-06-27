from __future__ import annotations

import csv
import io
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
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

    def stats_by_asi(self) -> list[dict[str, Any]]:
        counts: dict[str, dict[str, Any]] = {}
        with self._connect() as conn:
            rows = conn.execute("SELECT detections FROM audit_events").fetchall()

        for row in rows:
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
