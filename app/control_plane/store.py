from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.audit.store import AuditStore


class ControlPlaneStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        AuditStore(self.db_path).initialize()

    def insert_policy_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        row = {
            "id": bundle["id"],
            "created_at": bundle["created_at"],
            "activated_at": bundle.get("activated_at"),
            "source": bundle["source"],
            "node_id": bundle["node_id"],
            "config_hash": bundle["config_hash"],
            "policy_hash": bundle["policy_hash"],
            "signature": bundle["signature"],
            "signing_key_env": bundle["signing_key_env"],
            "status": bundle.get("status", "created"),
            "bundle": json.dumps(bundle["bundle"], separators=(",", ":")),
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO policy_bundles (
                  id, created_at, activated_at, source, node_id, config_hash,
                  policy_hash, signature, signing_key_env, status, bundle
                ) VALUES (
                  :id, :created_at, :activated_at, :source, :node_id,
                  :config_hash, :policy_hash, :signature, :signing_key_env,
                  :status, :bundle
                )
                """,
                row,
            )
        return _decode_policy_bundle_row(row)

    def list_policy_bundles(self, *, limit: int = 100, offset: int = 0, newest_first: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM policy_bundles ORDER BY created_at " + ("DESC" if newest_first else "ASC") + " LIMIT ? OFFSET ?"
        with self._connect() as conn:
            rows = conn.execute(sql, (max(1, min(limit, 500)), max(0, offset))).fetchall()
        return [_decode_policy_bundle_row(dict(row)) for row in rows]

    def export_policy_bundles(self, *, start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
        where, params = _time_filter("created_at", start, end)
        sql = "SELECT * FROM policy_bundles"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_decode_policy_bundle_row(dict(row)) for row in rows]

    def get_policy_bundle(self, bundle_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM policy_bundles WHERE id = ?", (bundle_id,)).fetchone()
        return _decode_policy_bundle_row(dict(row)) if row is not None else None

    def active_policy_bundle(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM policy_bundles WHERE status = 'active' ORDER BY activated_at DESC, created_at DESC LIMIT 1"
            ).fetchone()
        return _decode_policy_bundle_row(dict(row)) if row is not None else None

    def activate_policy_bundle(self, bundle_id: str) -> dict[str, Any] | None:
        activated_at = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM policy_bundles WHERE id = ?", (bundle_id,)).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE policy_bundles SET status = 'retired' WHERE status = 'active'")
            conn.execute(
                "UPDATE policy_bundles SET status = 'active', activated_at = ? WHERE id = ?",
                (activated_at, bundle_id),
            )
            updated = conn.execute("SELECT * FROM policy_bundles WHERE id = ?", (bundle_id,)).fetchone()
        return _decode_policy_bundle_row(dict(updated)) if updated is not None else None

    def record_heartbeat(self, heartbeat: dict[str, Any]) -> dict[str, Any]:
        row = {
            "id": heartbeat.get("id") or str(uuid.uuid4()),
            "ts": heartbeat.get("ts") or datetime.now(UTC).isoformat(),
            "node_id": heartbeat["node_id"],
            "version": heartbeat["version"],
            "config_hash": heartbeat["config_hash"],
            "policy_hash": heartbeat["policy_hash"],
            "diagnostics_status": heartbeat["diagnostics_status"],
            "counts_summary": json.dumps(heartbeat.get("counts_summary", {}), separators=(",", ":")),
            "metadata": json.dumps(heartbeat.get("metadata", {}), separators=(",", ":")),
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO fleet_heartbeats (
                  id, ts, node_id, version, config_hash, policy_hash,
                  diagnostics_status, counts_summary, metadata
                ) VALUES (
                  :id, :ts, :node_id, :version, :config_hash, :policy_hash,
                  :diagnostics_status, :counts_summary, :metadata
                )
                """,
                row,
            )
        return _decode_heartbeat_row(row)

    def list_fleet_heartbeats(self, *, limit: int = 100, offset: int = 0, newest_first: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM fleet_heartbeats ORDER BY ts " + ("DESC" if newest_first else "ASC") + " LIMIT ? OFFSET ?"
        with self._connect() as conn:
            rows = conn.execute(sql, (max(1, min(limit, 500)), max(0, offset))).fetchall()
        return [_decode_heartbeat_row(dict(row)) for row in rows]

    def export_fleet_heartbeats(self, *, start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
        where, params = _time_filter("ts", start, end)
        sql = "SELECT * FROM fleet_heartbeats"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_decode_heartbeat_row(dict(row)) for row in rows]

    def list_fleet_nodes(self) -> list[dict[str, Any]]:
        sql = """
        SELECT h.*
        FROM fleet_heartbeats h
        JOIN (
          SELECT node_id, MAX(ts) AS latest_ts
          FROM fleet_heartbeats
          GROUP BY node_id
        ) latest ON h.node_id = latest.node_id AND h.ts = latest.latest_ts
        ORDER BY h.node_id ASC
        """
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()
        return [_decode_heartbeat_row(dict(row)) for row in rows]

    def record_drift_event(self, drift: dict[str, Any]) -> dict[str, Any]:
        row = {
            "id": drift.get("id") or str(uuid.uuid4()),
            "ts": drift.get("ts") or datetime.now(UTC).isoformat(),
            "node_id": drift["node_id"],
            "active_bundle_id": drift.get("active_bundle_id"),
            "expected_config_hash": drift.get("expected_config_hash"),
            "running_config_hash": drift["running_config_hash"],
            "expected_policy_hash": drift.get("expected_policy_hash"),
            "running_policy_hash": drift["running_policy_hash"],
            "severity": drift["severity"],
            "status": drift["status"],
            "evidence": json.dumps(drift.get("evidence", {}), separators=(",", ":")),
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO policy_drift_events (
                  id, ts, node_id, active_bundle_id, expected_config_hash,
                  running_config_hash, expected_policy_hash, running_policy_hash,
                  severity, status, evidence
                ) VALUES (
                  :id, :ts, :node_id, :active_bundle_id, :expected_config_hash,
                  :running_config_hash, :expected_policy_hash, :running_policy_hash,
                  :severity, :status, :evidence
                )
                """,
                row,
            )
        return _decode_drift_row(row)

    def list_drift_events(self, *, limit: int = 100, offset: int = 0, newest_first: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM policy_drift_events ORDER BY ts " + ("DESC" if newest_first else "ASC") + " LIMIT ? OFFSET ?"
        with self._connect() as conn:
            rows = conn.execute(sql, (max(1, min(limit, 500)), max(0, offset))).fetchall()
        return [_decode_drift_row(dict(row)) for row in rows]

    def export_drift_events(self, *, start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
        where, params = _time_filter("ts", start, end)
        sql = "SELECT * FROM policy_drift_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_decode_drift_row(dict(row)) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        if self.db_path != ":memory:":
            Path(self.db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn


def _time_filter(column: str, start: str | None, end: str | None) -> tuple[list[str], list[object]]:
    where: list[str] = []
    params: list[object] = []
    if start:
        where.append(f"{column} >= ?")
        params.append(start)
    if end:
        where.append(f"{column} <= ?")
        params.append(end)
    return where, params


def _decode_policy_bundle_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["bundle"] = json.loads(decoded.get("bundle") or "{}")
    decoded["request_id"] = decoded.get("id")
    decoded["direction"] = "control_policy_bundle"
    decoded["upstream_model"] = decoded.get("source")
    return decoded


def _decode_heartbeat_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["counts_summary"] = json.loads(decoded.get("counts_summary") or "{}")
    decoded["metadata"] = json.loads(decoded.get("metadata") or "{}")
    decoded["request_id"] = decoded.get("id")
    decoded["direction"] = "control_heartbeat"
    decoded["upstream_model"] = decoded.get("node_id")
    return decoded


def _decode_drift_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["evidence"] = json.loads(decoded.get("evidence") or "{}")
    decoded["request_id"] = decoded.get("id")
    decoded["direction"] = "control_drift"
    decoded["upstream_model"] = decoded.get("node_id")
    return decoded

