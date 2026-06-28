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

CREATE TABLE IF NOT EXISTS tool_call_events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  request_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  session_id TEXT,
  tool_name TEXT NOT NULL,
  action TEXT NOT NULL,
  method TEXT NOT NULL,
  target_host TEXT,
  target TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('allow', 'block', 'approval_required')),
  risk_level TEXT NOT NULL,
  approval_id TEXT,
  latency_ms INTEGER NOT NULL,
  detections TEXT NOT NULL,
  reasons TEXT NOT NULL,
  policy_snapshot TEXT NOT NULL,
  client_meta TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_call_events_ts ON tool_call_events (ts);
CREATE INDEX IF NOT EXISTS idx_tool_call_events_request_id ON tool_call_events (request_id);
CREATE INDEX IF NOT EXISTS idx_tool_call_events_agent_id ON tool_call_events (agent_id);
CREATE INDEX IF NOT EXISTS idx_tool_call_events_tool_name ON tool_call_events (tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_call_events_decision ON tool_call_events (decision);

CREATE TABLE IF NOT EXISTS tool_approvals (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  request_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  action TEXT NOT NULL,
  method TEXT NOT NULL,
  target_host TEXT,
  risk_level TEXT NOT NULL,
  reason TEXT NOT NULL,
  approver TEXT,
  comment TEXT,
  payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_approvals_status ON tool_approvals (status);
CREATE INDEX IF NOT EXISTS idx_tool_approvals_request_id ON tool_approvals (request_id);
CREATE INDEX IF NOT EXISTS idx_tool_approvals_agent_tool ON tool_approvals (agent_id, tool_name);

CREATE TABLE IF NOT EXISTS context_events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  request_id TEXT NOT NULL,
  framework TEXT NOT NULL,
  hook_type TEXT NOT NULL CHECK (hook_type IN ('memory_write', 'retrieval_context')),
  agent_id TEXT NOT NULL,
  session_id TEXT,
  source_ref TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('allow', 'block', 'redact', 'flag')),
  latency_ms INTEGER NOT NULL,
  scanners_run TEXT NOT NULL,
  detections TEXT NOT NULL,
  policy_snapshot TEXT NOT NULL,
  client_meta TEXT NOT NULL,
  error TEXT
);

CREATE INDEX IF NOT EXISTS idx_context_events_ts ON context_events (ts);
CREATE INDEX IF NOT EXISTS idx_context_events_request_id ON context_events (request_id);
CREATE INDEX IF NOT EXISTS idx_context_events_framework ON context_events (framework);
CREATE INDEX IF NOT EXISTS idx_context_events_hook_type ON context_events (hook_type);
CREATE INDEX IF NOT EXISTS idx_context_events_agent_id ON context_events (agent_id);
CREATE INDEX IF NOT EXISTS idx_context_events_decision ON context_events (decision);

CREATE TABLE IF NOT EXISTS predeploy_runs (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  suite TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('pass', 'fail', 'warn', 'error')),
  adapters TEXT NOT NULL,
  targets TEXT NOT NULL,
  thresholds TEXT NOT NULL,
  summary TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  output_dir TEXT,
  error TEXT
);

CREATE INDEX IF NOT EXISTS idx_predeploy_runs_ts ON predeploy_runs (ts);
CREATE INDEX IF NOT EXISTS idx_predeploy_runs_suite ON predeploy_runs (suite);
CREATE INDEX IF NOT EXISTS idx_predeploy_runs_decision ON predeploy_runs (decision);

CREATE TABLE IF NOT EXISTS predeploy_findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  adapter TEXT NOT NULL,
  finding_type TEXT NOT NULL,
  target TEXT NOT NULL,
  severity TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('pass', 'fail', 'warn', 'error')),
  control TEXT NOT NULL,
  asi_id TEXT,
  llm_id TEXT,
  owasp_llm TEXT NOT NULL,
  owasp_asi TEXT NOT NULL,
  nist_rmf TEXT NOT NULL,
  nist_genai TEXT NOT NULL,
  evidence TEXT NOT NULL,
  metadata TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES predeploy_runs (id)
);

CREATE INDEX IF NOT EXISTS idx_predeploy_findings_run_id ON predeploy_findings (run_id);
CREATE INDEX IF NOT EXISTS idx_predeploy_findings_adapter ON predeploy_findings (adapter);
CREATE INDEX IF NOT EXISTS idx_predeploy_findings_decision ON predeploy_findings (decision);
CREATE INDEX IF NOT EXISTS idx_predeploy_findings_control ON predeploy_findings (control);
