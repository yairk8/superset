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
"""CLI report generator for Devin auto-remediation analytics.

Usage:
    python report.py                  # Print summary to stdout
    python report.py --json           # Print JSON report
    python report.py --refresh        # Refresh session statuses first
    python report.py --output report.html  # Write HTML report
"""

from __future__ import annotations

import argparse
import json  # noqa: TID251
import logging
import os
import sys
from datetime import datetime, timezone

from devin_client import DevinClient
from monitor import SessionMonitor

logger = logging.getLogger(__name__)


def _format_duration(seconds: float) -> str:
    """Convert seconds to a human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def print_text_report(monitor: SessionMonitor) -> None:
    """Print a plain-text summary report to stdout."""
    analytics = monitor.get_analytics()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print("=" * 60)
    print(f"  Devin Issue Remediation Report  —  {ts}")
    print("=" * 60)
    print()
    print(f"  Total Sessions:      {analytics.total_sessions}")
    print(f"  Active:              {analytics.active_sessions}")
    print(f"  Completed:           {analytics.completed_sessions}")
    print(f"  Successful:          {analytics.successful_sessions}")
    print(f"  Failed:              {analytics.failed_sessions}")
    print(f"  Pending:             {analytics.pending_sessions}")
    print(f"  Success Rate:        {analytics.success_rate:.1f}%")
    print(f"  PRs Created:         {analytics.prs_created}")
    if analytics.avg_resolution_seconds > 0:
        print(
            f"  Avg Resolution Time: "
            f"{_format_duration(analytics.avg_resolution_seconds)}"
        )
    print()

    if analytics.records:
        print("-" * 60)
        print(f"  {'Issue':<30} {'Outcome':<12} {'PRs':>4}")
        print("-" * 60)
        for rec in analytics.records:
            title = (
                rec.issue_title[:28] + ".."
                if len(rec.issue_title) > 30
                else rec.issue_title
            )
            pr_count = len(rec.pull_request_urls)
            print(f"  {title:<30} {rec.outcome:<12} {pr_count:>4}")
        print("-" * 60)

    print()
    verdict = (
        "HEALTHY"
        if analytics.success_rate >= 70
        else "NEEDS ATTENTION"
        if analytics.success_rate >= 40
        else "CRITICAL"
    )
    print(f"  System Status: {verdict}")
    print()


def generate_html_report(monitor: SessionMonitor) -> str:
    """Generate a standalone HTML report."""
    analytics = monitor.get_analytics()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = ""
    for rec in analytics.records:
        prs = ", ".join(f'<a href="{u}">PR</a>' for u in rec.pull_request_urls) or "—"
        session_link = (
            f'<a href="{rec.session_url}">View</a>' if rec.session_url else "—"
        )
        issue_link = (
            f'<a href="{rec.issue_url}">{rec.issue_title}</a>'
            if rec.issue_url
            else rec.issue_title
        )
        rows += f"""<tr>
            <td>{issue_link}</td>
            <td>{rec.status}</td>
            <td><span class="badge badge-{rec.outcome}">{rec.outcome}</span></td>
            <td>{prs}</td>
            <td>{session_link}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Remediation Report — {ts}</title>
<style>
  body {{ font-family: system-ui; background: #0d1117; color: #c9d1d9;
         padding: 32px; max-width: 900px; margin: 0 auto; }}
  h1 {{ color: #f0f6fc; }} .ts {{ color: #8b949e; font-size: 14px; }}
  .grid {{ display: grid; grid-template-columns: repeat(3, 1fr);
           gap: 12px; margin: 24px 0; }}
  .card {{ background: #161b22; border: 1px solid #30363d;
           border-radius: 8px; padding: 16px; text-align: center; }}
  .val {{ font-size: 28px; font-weight: 700; color: #f0f6fc; }}
  .lbl {{ font-size: 12px; color: #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22;
           border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; padding: 10px 14px; text-align: left;
       font-size: 11px; text-transform: uppercase; color: #8b949e; }}
  td {{ padding: 10px 14px; border-top: 1px solid #30363d; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 12px; }}
  .badge-success {{ background: #23863620; color: #3fb950; }}
  .badge-failure {{ background: #f8514920; color: #f85149; }}
  .badge-in_progress {{ background: #d2992220; color: #d29922; }}
  .badge-pending {{ background: #8b949e20; color: #8b949e; }}
  .status {{ margin: 24px 0; padding: 16px; border-radius: 8px;
             font-weight: 600; text-align: center; }}
  .status-healthy {{ background: #23863620; color: #3fb950;
                     border: 1px solid #23863650; }}
  .status-attention {{ background: #d2992220; color: #d29922;
                       border: 1px solid #d2992250; }}
  .status-critical {{ background: #f8514920; color: #f85149;
                      border: 1px solid #f8514950; }}
</style></head><body>
<h1>Devin Issue Remediation Report</h1>
<p class="ts">Generated: {ts}</p>
<div class="grid">
  <div class="card"><div class="val">{analytics.total_sessions}</div>
    <div class="lbl">Total</div></div>
  <div class="card"><div class="val">{analytics.successful_sessions}</div>
    <div class="lbl">Successful</div></div>
  <div class="card"><div class="val">{analytics.success_rate:.0f}%</div>
    <div class="lbl">Success Rate</div></div>
  <div class="card"><div class="val">{analytics.active_sessions}</div>
    <div class="lbl">Active</div></div>
  <div class="card"><div class="val">{analytics.failed_sessions}</div>
    <div class="lbl">Failed</div></div>
  <div class="card"><div class="val">{analytics.prs_created}</div>
    <div class="lbl">PRs Created</div></div>
</div>
<table><thead><tr><th>Issue</th><th>Status</th><th>Outcome</th>
<th>PRs</th><th>Session</th></tr></thead><tbody>{rows}</tbody></table>
<div class="status status-{
        "healthy"
        if analytics.success_rate >= 70
        else "attention"
        if analytics.success_rate >= 40
        else "critical"
    }">
  System Status: {
        "HEALTHY"
        if analytics.success_rate >= 70
        else "NEEDS ATTENTION"
        if analytics.success_rate >= 40
        else "CRITICAL"
    }
</div></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Devin remediation report")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--refresh", action="store_true", help="Refresh first")
    parser.add_argument("--output", type=str, help="Write HTML report to file")
    args = parser.parse_args()

    api_key = os.environ.get("DEVIN_API_KEY", "")
    org_id = os.environ.get("DEVIN_ORG_ID", "")

    if not api_key or not org_id:
        print("Error: DEVIN_API_KEY and DEVIN_ORG_ID must be set", file=sys.stderr)
        sys.exit(1)

    client = DevinClient(api_key=api_key, org_id=org_id)
    monitor = SessionMonitor(client)

    if args.refresh:
        monitor.refresh()

    if args.json:
        analytics = monitor.get_analytics()
        print(json.dumps(analytics.to_dict(), indent=2))
    elif args.output:
        html = generate_html_report(monitor)
        with open(args.output, "w") as f:
            f.write(html)
        print(f"Report written to {args.output}")
    else:
        print_text_report(monitor)

    client.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
