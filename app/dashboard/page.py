from __future__ import annotations


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Amby Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7f9;
      --panel: #ffffff;
      --ink: #17202a;
      --muted: #687684;
      --line: #d8dee6;
      --accent: #0f766e;
      --warn: #b45309;
      --bad: #b91c1c;
      --ok: #166534;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.4 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 16px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      position: sticky;
      top: 0;
      z-index: 2;
    }
    h1 { margin: 0; font-size: 20px; letter-spacing: 0; }
    main { max-width: 1280px; margin: 0 auto; padding: 20px 24px 32px; }
    .banner {
      border: 1px solid #f3c77a;
      background: #fff8e8;
      color: #6b4100;
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
      gap: 16px;
      align-items: start;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    section h2 {
      margin: 0;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      font-size: 15px;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      align-items: center;
    }
    input, select, button {
      height: 34px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
      padding: 0 10px;
      font: inherit;
    }
    button {
      background: var(--accent);
      border-color: var(--accent);
      color: white;
      cursor: pointer;
      font-weight: 600;
    }
    button.secondary {
      background: #fff;
      color: var(--ink);
      border-color: var(--line);
    }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th { color: var(--muted); font-weight: 600; font-size: 12px; }
    .pill {
      display: inline-flex;
      align-items: center;
      height: 22px;
      padding: 0 8px;
      border-radius: 999px;
      background: #eef2f6;
      color: #344054;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .pill.block { background: #fee2e2; color: var(--bad); }
    .pill.redact { background: #ffedd5; color: var(--warn); }
    .pill.flag { background: #e0f2fe; color: #075985; }
    .pill.allow { background: #dcfce7; color: var(--ok); }
    .stats { padding: 12px 14px; display: grid; gap: 10px; }
    .bar-row { display: grid; grid-template-columns: 72px 1fr 42px; gap: 8px; align-items: center; }
    .bar { height: 10px; background: #e5e7eb; border-radius: 999px; overflow: hidden; }
    .bar span { display: block; height: 100%; background: var(--accent); min-width: 2px; }
    .status-row { display: grid; grid-template-columns: 92px 1fr 48px; gap: 8px; align-items: center; }
    .status {
      display: inline-flex;
      align-items: center;
      height: 22px;
      padding: 0 8px;
      border-radius: 6px;
      background: #eef2f6;
      color: #344054;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .status.implemented { background: #dcfce7; color: var(--ok); }
    .status.partial { background: #e0f2fe; color: #075985; }
    .status.planned { background: #f3f4f6; color: #4b5563; }
    .control-list { display: grid; gap: 8px; }
    .control-item { border-top: 1px solid var(--line); padding-top: 8px; }
    .control-title { font-weight: 700; }
    .events { max-height: 380px; overflow: auto; }
    .event-item { padding: 10px 14px; border-bottom: 1px solid var(--line); }
    .event-meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .empty { padding: 20px 14px; color: var(--muted); }
    @media (max-width: 900px) {
      header { padding: 14px 16px; }
      main { padding: 16px; }
      .grid { grid-template-columns: 1fr; }
      table { min-width: 760px; }
      .table-wrap { overflow-x: auto; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Amby</h1>
    <button id="demoBtn" title="Create sample guardrail events">Inject Demo</button>
  </header>
  <main>
    <div id="exposureBanner" class="banner" hidden>Dashboard is unauthenticated. Bind to localhost or place it behind private network controls.</div>
    <div class="grid">
      <div>
        <section>
          <h2>Audit Events</h2>
          <div class="toolbar">
            <input id="query" placeholder="Search request, model, ASI">
            <select id="decision">
              <option value="">All decisions</option>
              <option value="block">Block</option>
              <option value="redact">Redact</option>
              <option value="flag">Flag</option>
              <option value="allow">Allow</option>
            </select>
            <button class="secondary" id="refreshBtn">Refresh</button>
            <button class="secondary" id="jsonBtn">JSON</button>
            <button class="secondary" id="csvBtn">CSV</button>
            <button class="secondary" id="evidenceBtn">Evidence</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style="width: 160px">Time</th>
                  <th style="width: 110px">Decision</th>
                  <th style="width: 90px">Dir</th>
                  <th style="width: 130px">Model</th>
                  <th>Detections</th>
                  <th style="width: 90px">Latency</th>
                </tr>
              </thead>
              <tbody id="eventsBody"></tbody>
            </table>
          </div>
        </section>
      </div>
      <div>
        <section>
          <h2>ASI Distribution</h2>
          <div id="stats" class="stats"></div>
        </section>
        <section style="margin-top: 16px">
          <h2>Mythos Readiness</h2>
          <div id="mythos" class="stats"></div>
        </section>
        <section style="margin-top: 16px">
          <h2>Live Tail</h2>
          <div id="live" class="events"></div>
        </section>
      </div>
    </div>
  </main>
  <script>
    const eventsBody = document.getElementById('eventsBody');
    const statsEl = document.getElementById('stats');
    const mythosEl = document.getElementById('mythos');
    const liveEl = document.getElementById('live');
    const queryEl = document.getElementById('query');
    const decisionEl = document.getElementById('decision');

    if (!['localhost', '127.0.0.1', '::1'].includes(location.hostname)) {
      document.getElementById('exposureBanner').hidden = false;
    }

    function pill(decision) {
      return `<span class="pill ${decision}">${decision}</span>`;
    }

    function summarizeDetections(event) {
      if (!event.detections.length) return '<span style="color: var(--muted)">none</span>';
      return event.detections.map(d => `${d.asi_id} ${d.scanner} ${d.action}`).join('<br>');
    }

    function statusBadge(status) {
      return `<span class="status ${status}">${status}</span>`;
    }

    async function loadEvents() {
      const params = new URLSearchParams({ limit: '100' });
      if (queryEl.value.trim()) params.set('q', queryEl.value.trim());
      if (decisionEl.value) params.set('decision', decisionEl.value);
      const res = await fetch(`/audit/events?${params}`);
      const rows = await res.json();
      eventsBody.innerHTML = rows.map(event => `
        <tr>
          <td>${new Date(event.ts).toLocaleString()}</td>
          <td>${pill(event.decision)}</td>
          <td>${event.direction}</td>
          <td>${event.upstream_model}</td>
          <td>${summarizeDetections(event)}</td>
          <td>${event.latency_ms} ms</td>
        </tr>
      `).join('');
      if (!rows.length) {
        eventsBody.innerHTML = '<tr><td colspan="6" class="empty">No audit events</td></tr>';
      }
    }

    async function loadStats() {
      const res = await fetch('/stats/asi');
      const rows = await res.json();
      const max = Math.max(1, ...rows.map(row => row.count));
      statsEl.innerHTML = rows.map(row => `
        <div class="bar-row">
          <strong>${row.asi_id}</strong>
          <div class="bar"><span style="width: ${(row.count / max) * 100}%"></span></div>
          <span>${row.count}</span>
        </div>
      `).join('') || '<div class="empty">No ASI detections</div>';
    }

    async function loadMythos() {
      const res = await fetch('/stats/mythos');
      const payload = await res.json();
      const counts = Object.entries(payload.status_counts).map(([status, count]) => `
        <div class="status-row">
          ${statusBadge(status)}
          <div class="bar"><span style="width: ${(count / payload.controls.length) * 100}%"></span></div>
          <span>${count}</span>
        </div>
      `).join('');
      const visibleControls = payload.controls
        .filter(control => ['implemented', 'partial'].includes(control.status))
        .slice(0, 5)
        .map(control => `
          <div class="control-item">
            <div class="control-title">${control.control_id} ${control.title}</div>
            <div class="event-meta">${statusBadge(control.status)} evidence: ${control.evidence_present ? 'yes' : 'no'} · ${control.roadmap_phase}</div>
          </div>
        `).join('');
      mythosEl.innerHTML = counts + `<div class="control-list">${visibleControls}</div>`;
    }

    function prependLive(event) {
      const item = document.createElement('div');
      item.className = 'event-item';
      item.innerHTML = `${pill(event.decision)} ${event.direction} ${event.upstream_model}
        <div class="event-meta">${new Date(event.ts).toLocaleTimeString()} ${event.request_id}</div>`;
      liveEl.prepend(item);
      while (liveEl.children.length > 40) liveEl.removeChild(liveEl.lastChild);
    }

    async function refresh() {
      await Promise.all([loadEvents(), loadStats(), loadMythos()]);
    }

    document.getElementById('refreshBtn').addEventListener('click', refresh);
    queryEl.addEventListener('input', () => window.clearTimeout(window.searchTimer) || (window.searchTimer = window.setTimeout(loadEvents, 250)));
    decisionEl.addEventListener('change', loadEvents);
    document.getElementById('jsonBtn').addEventListener('click', () => { location.href = '/audit/export?format=json'; });
    document.getElementById('csvBtn').addEventListener('click', () => { location.href = '/audit/export?format=csv'; });
    document.getElementById('evidenceBtn').addEventListener('click', async () => {
      const res = await fetch('/audit/evidence', { method: 'POST' });
      const payload = await res.json();
      alert(`Evidence package created\\n${payload.package_dir}\\n${payload.manifest_hash}\\nMythos: ${JSON.stringify(payload.mythos_readiness.status_counts)}`);
    });
    document.getElementById('demoBtn').addEventListener('click', async () => {
      await fetch('/demo/inject', { method: 'POST' });
      await refresh();
    });

    const stream = new EventSource('/events/stream');
    stream.onmessage = event => {
      const row = JSON.parse(event.data);
      prependLive(row);
      refresh();
    };

    refresh();
  </script>
</body>
</html>"""
