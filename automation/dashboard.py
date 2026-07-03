# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""FastAPI dashboard for monitoring Devin auto-remediation sessions.

Provides:
  - GET /              HTML analytics dashboard
  - GET /api/analytics JSON analytics payload
  - GET /api/sessions  List all tracked sessions
  - POST /api/refresh  Trigger a manual refresh of session statuses
  - POST /webhook      GitHub issue webhook receiver (standalone mode)
"""

from __future__ import annotations

import hashlib
import hmac
import json  # noqa: TID251
import logging
import os
from dataclasses import asdict
from typing import Optional

from devin_client import DevinClient
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from monitor import SessionMonitor

logger = logging.getLogger(__name__)

DEVIN_API_KEY = os.environ.get("DEVIN_API_KEY", "")
DEVIN_ORG_ID = os.environ.get("DEVIN_ORG_ID", "")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
TARGET_REPO = os.environ.get("TARGET_REPO", "yairk8/superset")
REMEDIATION_LABEL = os.environ.get("REMEDIATION_LABEL", "devin-fix")

app = FastAPI(title="Devin Issue Remediation Dashboard")

client: Optional[DevinClient] = None
monitor_instance: Optional[SessionMonitor] = None


def _get_monitor() -> SessionMonitor:
    global client, monitor_instance
    if monitor_instance is None:
        if not DEVIN_API_KEY or not DEVIN_ORG_ID:
            raise HTTPException(
                status_code=500,
                detail="DEVIN_API_KEY and DEVIN_ORG_ID must be set",
            )
        client = DevinClient(api_key=DEVIN_API_KEY, org_id=DEVIN_ORG_ID)
        monitor_instance = SessionMonitor(client)
    return monitor_instance


def _verify_github_signature(payload: bytes, signature: str) -> bool:
    """Verify the GitHub webhook HMAC-SHA256 signature."""
    if not GITHUB_WEBHOOK_SECRET:
        return True
    expected = (
        "sha256="
        + hmac.new(GITHUB_WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    )
    return hmac.compare_digest(expected, signature)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Devin Issue Remediation Dashboard</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d;
          --text: #c9d1d9; --green: #3fb950; --red: #f85149;
          --blue: #58a6ff; --yellow: #d29922; --accent: #1f6feb; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family:
         -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial,
         sans-serif; padding: 24px; }
  h1 { color: #f0f6fc; margin-bottom: 8px; font-size: 24px; }
  .subtitle { color: #8b949e; margin-bottom: 24px; font-size: 14px; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit,
             minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .metric-card { background: var(--card); border: 1px solid var(--border);
                 border-radius: 8px; padding: 20px; }
  .metric-value { font-size: 32px; font-weight: 700; color: #f0f6fc; }
  .metric-label { font-size: 13px; color: #8b949e; margin-top: 4px; }
  .metric-card.success .metric-value { color: var(--green); }
  .metric-card.failure .metric-value { color: var(--red); }
  .metric-card.active .metric-value { color: var(--yellow); }
  .metric-card.rate .metric-value { color: var(--blue); }
  table { width: 100%; border-collapse: collapse; background: var(--card);
          border: 1px solid var(--border); border-radius: 8px;
          overflow: hidden; }
  th { background: #21262d; text-align: left; padding: 12px 16px;
       font-size: 12px; text-transform: uppercase; color: #8b949e;
       letter-spacing: 0.5px; }
  td { padding: 12px 16px; border-top: 1px solid var(--border);
       font-size: 14px; }
  tr:hover { background: #1c2128; }
  a { color: var(--blue); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
           font-size: 12px; font-weight: 600; }
  .badge-success { background: #23863620; color: var(--green); border:
                   1px solid #23863650; }
  .badge-failure { background: #f8514920; color: var(--red); border:
                   1px solid #f8514950; }
  .badge-active { background: #d2992220; color: var(--yellow); border:
                  1px solid #d2992250; }
  .badge-pending { background: #8b949e20; color: #8b949e; border:
                   1px solid #8b949e50; }
  .refresh-btn { background: var(--accent); color: #fff; border: none;
                 padding: 8px 16px; border-radius: 6px; cursor: pointer;
                 font-size: 14px; margin-bottom: 16px; }
  .refresh-btn:hover { background: #388bfd; }
  .header-row { display: flex; justify-content: space-between;
                align-items: center; margin-bottom: 24px; }
  .timestamp { color: #8b949e; font-size: 12px; }
  .section-title { font-size: 18px; font-weight: 600; color: #f0f6fc;
                   margin-bottom: 16px; }
  .empty { text-align: center; padding: 48px; color: #8b949e; }
</style>
</head>
<body>
<div class="header-row">
  <div>
    <h1>Devin Issue Remediation</h1>
    <p class="subtitle">Automated bug fixing powered by Devin AI</p>
  </div>
  <button class="refresh-btn" onclick="refresh()">Refresh</button>
</div>

<div class="metrics" id="metrics"></div>
<div class="section-title">Remediation Sessions</div>
<div id="table-container"></div>

<script>
async function loadData() {
  const resp = await fetch('/api/analytics');
  const data = await resp.json();
  renderMetrics(data);
  renderTable(data.records);
}

function renderMetrics(d) {
  document.getElementById('metrics').innerHTML = `
    <div class="metric-card">
      <div class="metric-value">${d.total_sessions}</div>
      <div class="metric-label">Total Sessions</div>
    </div>
    <div class="metric-card active">
      <div class="metric-value">${d.active_sessions}</div>
      <div class="metric-label">Active</div>
    </div>
    <div class="metric-card success">
      <div class="metric-value">${d.successful_sessions}</div>
      <div class="metric-label">Successful</div>
    </div>
    <div class="metric-card failure">
      <div class="metric-value">${d.failed_sessions}</div>
      <div class="metric-label">Failed</div>
    </div>
    <div class="metric-card rate">
      <div class="metric-value">${d.success_rate}%</div>
      <div class="metric-label">Success Rate</div>
    </div>
    <div class="metric-card">
      <div class="metric-value">${d.prs_created}</div>
      <div class="metric-label">PRs Created</div>
    </div>
  `;
}

function badgeClass(outcome) {
  return { success: 'badge-success', failure: 'badge-failure',
           in_progress: 'badge-active', pending: 'badge-pending' }
         [outcome] || 'badge-pending';
}

function renderTable(records) {
  if (!records.length) {
    document.getElementById('table-container').innerHTML =
      '<div class="empty">No remediation sessions tracked yet.<br>' +
      'Create a GitHub issue with the <code>devin-fix</code> label to start.</div>';
    return;
  }
  let html = `<table><thead><tr>
    <th>Issue</th><th>Status</th><th>Outcome</th>
    <th>PRs</th><th>Session</th></tr></thead><tbody>`;
  for (const r of records) {
    const prs = r.pull_request_urls.map(
      u => `<a href="${u}" target="_blank">PR</a>`).join(', ') || '—';
    const sessionLink = r.session_url
      ? `<a href="${r.session_url}" target="_blank">View</a>` : '—';
    const issueLink = r.issue_url
      ? `<a href="${r.issue_url}" target="_blank">${esc(r.issue_title)}</a>`
      : esc(r.issue_title);
    html += `<tr>
      <td>${issueLink}</td>
      <td>${r.status} ${r.status_detail ? '(' + esc(r.status_detail) + ')' : ''}</td>
      <td><span class="badge ${badgeClass(r.outcome)}">${r.outcome}</span></td>
      <td>${prs}</td>
      <td>${sessionLink}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  document.getElementById('table-container').innerHTML = html;
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

async function refresh() {
  await fetch('/api/refresh', { method: 'POST' });
  await loadData();
}

loadData();
setInterval(loadData, 30000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Render the analytics dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/api/analytics")
async def api_analytics() -> JSONResponse:
    """Return aggregated analytics as JSON."""
    mon = _get_monitor()
    analytics = mon.get_analytics()
    return JSONResponse(content=analytics.to_dict())


@app.get("/api/sessions")
async def api_sessions() -> JSONResponse:
    """Return all tracked remediation sessions."""
    mon = _get_monitor()
    return JSONResponse(content=[asdict(r) for r in mon.records])


@app.post("/api/refresh")
async def api_refresh() -> JSONResponse:
    """Manually trigger a refresh of all session statuses."""
    mon = _get_monitor()
    mon.refresh()
    analytics = mon.get_analytics()
    return JSONResponse(content=analytics.to_dict())


@app.post("/webhook")
async def github_webhook(request: Request) -> JSONResponse:
    """Receive GitHub issue webhook events (standalone mode).

    When an issue is opened or labeled with the remediation label,
    a Devin session is created to fix it.
    """
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    if not _verify_github_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = request.headers.get("x-github-event", "")
    if event != "issues":
        return JSONResponse(content={"status": "ignored", "event": event})

    payload = json.loads(body)
    action = payload.get("action", "")
    issue = payload.get("issue", {})
    labels = [lbl.get("name", "") for lbl in issue.get("labels", [])]

    should_process = (action == "opened" and REMEDIATION_LABEL in labels) or (
        action == "labeled"
        and payload.get("label", {}).get("name") == REMEDIATION_LABEL
    )

    if not should_process:
        return JSONResponse(
            content={"status": "skipped", "reason": "no matching label/action"}
        )

    issue_title = issue.get("title", "Untitled")
    issue_body = issue.get("body", "")
    issue_url = issue.get("html_url", "")
    issue_number = issue.get("number", 0)
    repo_full_name = payload.get("repository", {}).get("full_name", TARGET_REPO)

    prompt = (
        f"Fix the following issue in the {repo_full_name} repository.\n\n"
        f"Issue #{issue_number}: {issue_title}\n\n"
        f"{issue_body}\n\n"
        f"Requirements:\n"
        f"- Read the issue carefully and understand the bug or improvement needed\n"
        f"- Find the relevant code in the repository\n"
        f"- Implement the fix following the project's coding standards\n"
        f"- Run linters and tests to verify the fix\n"
        f"- Create a pull request with a clear description referencing issue "
        f"#{issue_number}\n"
    )

    mon = _get_monitor()
    if client is None:
        raise HTTPException(status_code=500, detail="Client not initialized")

    session = client.create_session(
        prompt=prompt,
        repos=[repo_full_name],
        tags=["auto-remediation", f"issue-{issue_number}"],
    )

    mon.track_session(
        session_id=session.session_id,
        issue_url=issue_url,
        issue_title=issue_title,
        session_url=session.url,
    )

    logger.info(
        "Created Devin session %s for issue #%s", session.session_id, issue_number
    )

    return JSONResponse(
        content={
            "status": "session_created",
            "session_id": session.session_id,
            "session_url": session.url,
            "issue": issue_url,
        }
    )


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8765)  # noqa: S104
