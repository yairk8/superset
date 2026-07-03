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
"""Devin REST API client for session management."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .config import Config
from .models import RemediationTask, ScannedIssue, SessionStatus

logger = logging.getLogger(__name__)


class DevinAPIError(Exception):
    """Raised when the Devin API returns an error."""


class DevinClient:
    """Thin wrapper around the Devin v1 REST API."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.base_url = config.devin_api_base
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {config.devin_api_key}",
                "Content-Type": "application/json",
            }
        )

    def create_session(
        self,
        prompt: str,
        *,
        tags: list[str] | None = None,
        title: str | None = None,
        max_acu_limit: int | None = None,
    ) -> dict[str, Any]:
        """Create a new Devin session.

        Returns dict with session_id, url, is_new_session.
        """
        payload: dict[str, Any] = {"prompt": prompt}
        if tags:
            payload["tags"] = tags
        if title:
            payload["title"] = title
        if max_acu_limit:
            payload["max_acu_limit"] = max_acu_limit

        resp = self.session.post(f"{self.base_url}/sessions", json=payload)
        if resp.status_code != 200:
            raise DevinAPIError(
                f"Failed to create session: {resp.status_code} {resp.text[:500]}"
            )
        return resp.json()

    def get_session(self, session_id: str) -> dict[str, Any]:
        """Get session details by ID."""
        resp = self.session.get(f"{self.base_url}/sessions/{session_id}")
        if resp.status_code != 200:
            raise DevinAPIError(
                f"Failed to get session {session_id}: "
                f"{resp.status_code} {resp.text[:500]}"
            )
        return resp.json()

    def list_sessions(
        self,
        *,
        tags: list[str] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List sessions, optionally filtered by tags."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if tags:
            params["tags"] = tags
        resp = self.session.get(f"{self.base_url}/sessions", params=params)
        if resp.status_code != 200:
            raise DevinAPIError(
                f"Failed to list sessions: {resp.status_code} {resp.text[:500]}"
            )
        return resp.json().get("sessions", [])

    def send_message(self, session_id: str, message: str) -> dict[str, Any]:
        """Send a message to an existing session."""
        resp = self.session.post(
            f"{self.base_url}/sessions/{session_id}/message",
            json={"message": message},
        )
        if resp.status_code != 200:
            raise DevinAPIError(
                f"Failed to message session {session_id}: "
                f"{resp.status_code} {resp.text[:500]}"
            )
        return resp.json()

    def poll_session_until_done(
        self,
        session_id: str,
        *,
        poll_interval: int = 30,
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Poll a session until it reaches a terminal state or times out."""
        terminal_statuses = {"finished", "exit", "error", "suspended"}
        terminal_status_details = {"finished", "inactivity", "error"}
        start = time.time()

        while time.time() - start < timeout:
            data = self.get_session(session_id)
            status = data.get("status_enum", data.get("status", ""))
            status_detail = data.get("status_detail", "")
            logger.info(
                "Session %s status=%s detail=%s",
                session_id,
                status,
                status_detail,
            )
            if status in terminal_statuses or status_detail in terminal_status_details:
                return data
            time.sleep(poll_interval)

        logger.warning("Session %s timed out after %ds", session_id, timeout)
        return self.get_session(session_id)


def build_remediation_prompt(issues: list[ScannedIssue], repo: str) -> str:
    """Build a self-contained prompt for a Devin session to fix issues."""
    issue_lines: list[str] = []
    for i, issue in enumerate(issues, 1):
        parts = [f"{i}. [{issue.severity.value.upper()}] {issue.title}"]
        if issue.package:
            parts.append(f"   Package: {issue.package}")
        if issue.current_version and issue.fixed_version:
            parts.append(
                f"   Version: {issue.current_version} -> {issue.fixed_version}"
            )
        if issue.file_path:
            parts.append(f"   File: {issue.file_path}")
        if issue.description:
            parts.append(f"   Details: {issue.description}")
        issue_lines.append("\n".join(parts))

    issues_block = "\n\n".join(issue_lines)

    return f"""You are remediating code issues in the repository {repo}.

Issues were detected by an automated scan. Fix them via a PR.

## Issues to Fix

{issues_block}

## Instructions

1. Clone the repository {repo}.
2. Create a new branch from the default branch.
3. For dependency vulnerabilities and upgrades:
   - Update the version pin in the relevant requirements/*.txt file.
   - Verify the new version is compatible by checking import statements.
4. For code quality issues:
   - Apply the fix described in each issue.
   - Follow the project's coding standards (type hints, no `any`, etc.).
5. Run `pre-commit run --all-files` to validate your changes.
6. Create a PR with a clear title and description explaining the fixes.
7. Tag the PR with `automated-remediation`.

Keep changes minimal and focused. Do not refactor unrelated code.
"""


def create_remediation_task(
    client: DevinClient,
    issues: list[ScannedIssue],
    task_id: str,
    config: Config,
) -> RemediationTask:
    """Create a Devin session to remediate a batch of issues."""
    task = RemediationTask(task_id=task_id, issues=issues)
    prompt = build_remediation_prompt(issues, config.repo)

    category = issues[0].category.value if issues else "mixed"
    title = f"[Auto-Remediation] Fix {len(issues)} {category} issue(s)"

    try:
        resp = client.create_session(
            prompt=prompt,
            tags=[config.run_tag, category, "automated"],
            title=title,
            max_acu_limit=config.max_acu_per_session,
        )
        task.devin_session_id = resp["session_id"]
        task.devin_session_url = resp.get("url", "")
        task.status = SessionStatus.RUNNING
        logger.info(
            "Created Devin session %s for task %s: %s",
            task.devin_session_id,
            task_id,
            task.devin_session_url,
        )
    except DevinAPIError as exc:
        task.status = SessionStatus.FAILED
        task.error_message = str(exc)
        logger.error("Failed to create session for task %s: %s", task_id, exc)

    return task
