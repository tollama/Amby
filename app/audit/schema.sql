CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  request_id TEXT NOT NULL,
  direction TEXT NOT NULL CHECK (direction IN ('input', 'output')),
  upstream_model TEXT NOT NULL,
  scanners_run TEXT NOT NULL,
  detections TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('allow', 'block', 'redact', 'flag')),
  latency_ms INTEGER NOT NULL,
  error TEXT,
  client_meta TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events (ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_request_id ON audit_events (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_decision ON audit_events (decision);
CREATE INDEX IF NOT EXISTS idx_audit_events_direction ON audit_events (direction);
