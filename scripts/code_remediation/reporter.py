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
"""Reporting and analytics for the code remediation system."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from .models import RunReport, SessionStatus

logger = logging.getLogger(__name__)


def generate_markdown_report(report: RunReport) -> str:
    """Produce a Markdown summary of a remediation run."""
    lines: list[str] = []
    lines.append("# Code Remediation Report")
    lines.append("")
    lines.append(f"**Run ID:** `{report.run_id}`")
    lines.append(f"**Started:** {report.started_at}")
    lines.append(f"**Completed:** {report.completed_at or 'in progress'}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Issues found | {report.total_issues_found} |")
    lines.append(f"| Sessions created | {report.tasks_created} |")
    lines.append(f"| Succeeded | {report.tasks_succeeded} |")
    lines.append(f"| Failed | {report.tasks_failed} |")
    lines.append(f"| Timed out | {report.tasks_timed_out} |")
    lines.append(f"| PRs created | {len(report.prs_created)} |")
    lines.append("")

    if report.issues_by_severity:
        lines.append("## Issues by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev, count in sorted(report.issues_by_severity.items()):
            lines.append(f"| {sev} | {count} |")
        lines.append("")

    if report.issues_by_category:
        lines.append("## Issues by Category")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for cat, count in sorted(report.issues_by_category.items()):
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    if report.prs_created:
        lines.append("## Pull Requests")
        lines.append("")
        for pr_url in report.prs_created:
            lines.append(f"- {pr_url}")
        lines.append("")

    if report.tasks:
        lines.append("## Task Details")
        lines.append("")
        lines.append("| Task | Status | Session | PR |")
        lines.append("|------|--------|---------|-----|")
        for task in report.tasks:
            session_link = (
                f"[link]({task.devin_session_url})" if task.devin_session_url else "—"
            )
            pr_link = f"[PR]({task.pr_url})" if task.pr_url else "—"
            status_icon = {
                SessionStatus.FINISHED.value: "done",
                SessionStatus.FAILED.value: "FAILED",
                SessionStatus.TIMED_OUT.value: "TIMEOUT",
                SessionStatus.RUNNING.value: "running",
                SessionStatus.PENDING.value: "pending",
            }.get(task.status.value, task.status.value)
            issue_summary = task.issues[0].title if task.issues else "—"
            lines.append(
                f"| {issue_summary} | {status_icon} | {session_link} | {pr_link} |"
            )
        lines.append("")

    success_rate = (
        f"{report.tasks_succeeded / report.tasks_created * 100:.0f}%"
        if report.tasks_created
        else "N/A"
    )
    lines.append("## Effectiveness")
    lines.append("")
    lines.append(f"- **Success rate:** {success_rate}")
    lines.append(f"- **Throughput:** {report.tasks_created} tasks in one run")
    lines.append(f"- **Coverage:** {report.total_issues_found} issues detected")
    lines.append("")

    return "\n".join(lines)


def generate_json_report(report: RunReport) -> str:
    """Produce a JSON representation of the run report."""
    return json.dumps(report.to_dict(), indent=2)


def save_report(report: RunReport, report_dir: str) -> tuple[str, str]:
    """Save both Markdown and JSON reports to disk. Returns (md_path, json_path)."""
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    md_path = os.path.join(report_dir, f"report_{timestamp}.md")
    json_path = os.path.join(report_dir, f"report_{timestamp}.json")

    md_content = generate_markdown_report(report)
    json_content = generate_json_report(report)

    with open(md_path, "w") as f:
        f.write(md_content)
    with open(json_path, "w") as f:
        f.write(json_content)

    logger.info("Reports saved to %s and %s", md_path, json_path)
    return md_path, json_path


def load_historical_reports(report_dir: str) -> list[RunReport]:
    """Load previously saved JSON reports for trend analysis."""
    reports: list[RunReport] = []
    report_path = Path(report_dir)
    if not report_path.exists():
        return reports

    for json_file in sorted(report_path.glob("report_*.json")):
        try:
            with open(json_file) as f:
                data = json.load(f)
            report = RunReport(
                run_id=data.get("run_id", ""),
                started_at=data.get("started_at", ""),
                completed_at=data.get("completed_at", ""),
                total_issues_found=data.get("total_issues_found", 0),
                issues_by_category=data.get("issues_by_category", {}),
                issues_by_severity=data.get("issues_by_severity", {}),
                tasks_created=data.get("tasks_created", 0),
                tasks_succeeded=data.get("tasks_succeeded", 0),
                tasks_failed=data.get("tasks_failed", 0),
                tasks_timed_out=data.get("tasks_timed_out", 0),
                prs_created=data.get("prs_created", []),
            )
            reports.append(report)
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Failed to load report %s: %s", json_file, exc)

    return reports


def generate_trend_summary(report_dir: str) -> str:
    """Generate a trend summary across all historical runs."""
    reports = load_historical_reports(report_dir)
    if not reports:
        return "No historical reports found."

    lines: list[str] = []
    lines.append("# Remediation Trend Summary")
    lines.append("")
    lines.append(f"**Total runs:** {len(reports)}")

    total_issues = sum(r.total_issues_found for r in reports)
    total_tasks = sum(r.tasks_created for r in reports)
    total_succeeded = sum(r.tasks_succeeded for r in reports)
    total_failed = sum(r.tasks_failed for r in reports)
    total_prs = sum(len(r.prs_created) for r in reports)

    lines.append(f"**Total issues found:** {total_issues}")
    lines.append(f"**Total sessions created:** {total_tasks}")
    lines.append(f"**Total succeeded:** {total_succeeded}")
    lines.append(f"**Total failed:** {total_failed}")
    lines.append(f"**Total PRs created:** {total_prs}")
    overall_rate = (
        f"{total_succeeded / total_tasks * 100:.0f}%" if total_tasks else "N/A"
    )
    lines.append(f"**Overall success rate:** {overall_rate}")
    lines.append("")

    lines.append("## Run History")
    lines.append("")
    lines.append("| Run | Date | Issues | Tasks | Succeeded | PRs |")
    lines.append("|-----|------|--------|-------|-----------|-----|")
    for r in reports[-10:]:
        date_str = r.started_at[:19] if r.started_at else "—"
        lines.append(
            f"| {r.run_id[:8]} | {date_str} "
            f"| {r.total_issues_found} | {r.tasks_created} "
            f"| {r.tasks_succeeded} | {len(r.prs_created)} |"
        )
    lines.append("")

    return "\n".join(lines)
