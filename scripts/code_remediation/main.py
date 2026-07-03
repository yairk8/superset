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
"""Main orchestrator for the code remediation automation.

Usage:
    # Scan only (no Devin sessions created)
    python -m scripts.code_remediation.main --scan-only

    # Full run (scan + create Devin sessions + poll + report)
    python -m scripts.code_remediation.main

    # Generate trend report from historical data
    python -m scripts.code_remediation.main --trends
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone

from .config import Config
from .devin_client import create_remediation_task, DevinClient
from .models import (
    IssueCategory,
    RemediationTask,
    RunReport,
    ScannedIssue,
    SessionStatus,
)
from .reporter import (
    generate_markdown_report,
    generate_trend_summary,
    save_report,
)
from .scanner import run_all_scans

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def group_issues(
    issues: list[ScannedIssue],
) -> dict[IssueCategory, list[ScannedIssue]]:
    """Group issues by category for batched remediation."""
    groups: dict[IssueCategory, list[ScannedIssue]] = {}
    for issue in issues:
        groups.setdefault(issue.category, []).append(issue)
    return groups


def run_scan_only(config: Config) -> RunReport:
    """Scan the repo and produce a report without creating Devin sessions."""
    run_id = uuid.uuid4().hex[:8]
    report = RunReport(run_id=run_id)

    logger.info("Starting scan-only run %s", run_id)
    issues = run_all_scans(config.repo_path)

    report.total_issues_found = len(issues)
    report.issues_by_severity = dict(Counter(i.severity.value for i in issues))
    report.issues_by_category = dict(Counter(i.category.value for i in issues))
    report.completed_at = datetime.now(timezone.utc).isoformat()

    md_path, json_path = save_report(report, config.report_path)
    logger.info("Scan complete. Report: %s", md_path)

    print(generate_markdown_report(report))
    return report


def run_full(config: Config) -> RunReport:
    """Scan, create Devin sessions for remediation, poll, and report."""
    run_id = uuid.uuid4().hex[:8]
    report = RunReport(run_id=run_id)

    logger.info("Starting full remediation run %s", run_id)

    # Step 1: Scan
    issues = run_all_scans(config.repo_path)
    report.total_issues_found = len(issues)
    report.issues_by_severity = dict(Counter(i.severity.value for i in issues))
    report.issues_by_category = dict(Counter(i.category.value for i in issues))

    if not issues:
        logger.info("No issues found. Nothing to remediate.")
        report.completed_at = datetime.now(timezone.utc).isoformat()
        save_report(report, config.report_path)
        print(generate_markdown_report(report))
        return report

    # Step 2: Group issues and create Devin sessions
    client = DevinClient(config)
    grouped = group_issues(issues)
    tasks: list[RemediationTask] = []

    for category, category_issues in grouped.items():
        batch_size = 5
        for batch_start in range(0, len(category_issues), batch_size):
            batch = category_issues[batch_start : batch_start + batch_size]
            task_id = f"{run_id}-{category.value}-{batch_start // batch_size}"
            task = create_remediation_task(client, batch, task_id, config)
            tasks.append(task)

            if len(tasks) >= config.max_concurrent_sessions:
                logger.info(
                    "Reached max concurrent sessions (%d), "
                    "waiting for current batch to finish",
                    config.max_concurrent_sessions,
                )
                _poll_tasks(client, tasks, config)

    # Step 3: Poll remaining tasks
    _poll_tasks(client, tasks, config)

    # Step 4: Compile report
    report.tasks = tasks
    report.tasks_created = len(tasks)
    report.tasks_succeeded = sum(1 for t in tasks if t.status == SessionStatus.FINISHED)
    report.tasks_failed = sum(1 for t in tasks if t.status == SessionStatus.FAILED)
    report.tasks_timed_out = sum(
        1 for t in tasks if t.status == SessionStatus.TIMED_OUT
    )
    report.prs_created = [t.pr_url for t in tasks if t.pr_url]
    report.completed_at = datetime.now(timezone.utc).isoformat()

    md_path, _ = save_report(report, config.report_path)
    logger.info("Full run complete. Report: %s", md_path)

    print(generate_markdown_report(report))
    return report


def _poll_tasks(
    client: DevinClient,
    tasks: list[RemediationTask],
    config: Config,
) -> None:
    """Poll all running tasks until they complete or time out."""
    running = [t for t in tasks if t.status == SessionStatus.RUNNING]
    for task in running:
        if not task.devin_session_id:
            continue
        try:
            result = client.poll_session_until_done(
                task.devin_session_id,
                poll_interval=config.poll_interval_seconds,
                timeout=config.session_timeout_seconds,
            )
            status = result.get("status_enum", result.get("status", ""))
            status_detail = result.get("status_detail", "")

            if status_detail == "finished" or status == "finished":
                task.status = SessionStatus.FINISHED
            elif status in ("error", "suspended") or status_detail == "error":
                task.status = SessionStatus.FAILED
                task.error_message = (
                    f"Session ended with status={status} detail={status_detail}"
                )
            else:
                task.status = SessionStatus.TIMED_OUT

            pr_info = result.get("pull_request")
            if pr_info and isinstance(pr_info, dict):
                task.pr_url = pr_info.get("url", "")

            task.completed_at = datetime.now(timezone.utc).isoformat()

        except Exception as exc:
            task.status = SessionStatus.FAILED
            task.error_message = str(exc)
            task.completed_at = datetime.now(timezone.utc).isoformat()
            logger.error("Error polling task %s: %s", task.task_id, exc)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Automated code remediation using the Devin API"
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Scan for issues without creating Devin sessions",
    )
    parser.add_argument(
        "--trends",
        action="store_true",
        help="Generate a trend summary from historical reports",
    )
    args = parser.parse_args()

    config = Config()

    if args.trends:
        print(generate_trend_summary(config.report_path))
        return

    if args.scan_only:
        run_scan_only(config)
        return

    if errors := config.validate():
        for err in errors:
            logger.error("Config error: %s", err)
        sys.exit(1)

    run_full(config)


if __name__ == "__main__":
    main()
