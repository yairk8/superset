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
"""Session monitor that tracks remediation sessions and computes analytics."""

from __future__ import annotations

import json  # noqa: TID251
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from devin_client import DevinClient, DevinSession

logger = logging.getLogger(__name__)

REMEDIATION_TAG = "auto-remediation"
STATE_FILE = Path(__file__).parent / "state" / "sessions.json"


@dataclass
class RemediationRecord:
    """A tracked remediation session with outcome metadata."""

    session_id: str
    issue_url: str
    issue_title: str
    status: str
    status_detail: str = ""
    created_at: str = ""
    updated_at: str = ""
    pull_request_urls: list[str] = field(default_factory=list)
    session_url: str = ""
    outcome: str = "pending"  # pending | success | failure | in_progress


@dataclass
class Analytics:
    """Aggregated analytics for engineering leaders."""

    total_sessions: int = 0
    active_sessions: int = 0
    completed_sessions: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    pending_sessions: int = 0
    success_rate: float = 0.0
    prs_created: int = 0
    avg_resolution_seconds: float = 0.0
    records: list[RemediationRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_sessions": self.total_sessions,
            "active_sessions": self.active_sessions,
            "completed_sessions": self.completed_sessions,
            "successful_sessions": self.successful_sessions,
            "failed_sessions": self.failed_sessions,
            "pending_sessions": self.pending_sessions,
            "success_rate": round(self.success_rate, 2),
            "prs_created": self.prs_created,
            "avg_resolution_seconds": round(self.avg_resolution_seconds, 1),
            "records": [asdict(r) for r in self.records],
        }


def _classify_outcome(session: DevinSession) -> str:
    """Determine whether a session succeeded, failed, or is still running."""
    if session.status in ("running",):
        if session.status_detail in ("finished", "waiting_for_user"):
            if session.pull_request_urls:
                return "success"
            return "failure"
        return "in_progress"
    if session.status == "exit":
        if session.pull_request_urls:
            return "success"
        return "failure"
    if session.status == "error":
        return "failure"
    if session.status == "suspended":
        return "in_progress"
    return "pending"


class SessionMonitor:
    """Polls the Devin API and maintains local state for remediation sessions."""

    def __init__(self, client: DevinClient) -> None:
        self.client = client
        self._records: dict[str, RemediationRecord] = {}
        self._load_state()

    def _load_state(self) -> None:
        """Load persisted session state from disk."""
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text())
                for item in data:
                    rec = RemediationRecord(**item)
                    self._records[rec.session_id] = rec
            except (json.JSONDecodeError, TypeError):
                logger.warning("Could not load state file, starting fresh")

    def _save_state(self) -> None:
        """Persist session state to disk."""
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = [asdict(r) for r in self._records.values()]
        STATE_FILE.write_text(json.dumps(data, indent=2))

    def track_session(
        self,
        session_id: str,
        issue_url: str,
        issue_title: str,
        session_url: str = "",
    ) -> RemediationRecord:
        """Register a new session for tracking."""
        rec = RemediationRecord(
            session_id=session_id,
            issue_url=issue_url,
            issue_title=issue_title,
            status="created",
            session_url=session_url,
            created_at=str(int(time.time())),
        )
        self._records[session_id] = rec
        self._save_state()
        return rec

    def refresh(self) -> None:
        """Poll the Devin API and update all tracked sessions."""
        for session_id, rec in self._records.items():
            if rec.outcome in ("success", "failure"):
                continue
            try:
                session = self.client.get_session(session_id)
                rec.status = session.status
                rec.status_detail = session.status_detail
                rec.updated_at = session.updated_at
                rec.pull_request_urls = session.pull_request_urls
                rec.outcome = _classify_outcome(session)
                if not rec.session_url and session.url:
                    rec.session_url = session.url
            except Exception:
                logger.exception("Failed to refresh session %s", session_id)
        self._save_state()

    def get_analytics(self) -> Analytics:
        """Compute aggregate analytics across all tracked sessions."""
        records = list(self._records.values())
        total = len(records)
        active = sum(1 for r in records if r.outcome == "in_progress")
        completed = sum(1 for r in records if r.outcome in ("success", "failure"))
        successful = sum(1 for r in records if r.outcome == "success")
        failed = sum(1 for r in records if r.outcome == "failure")
        pending = sum(1 for r in records if r.outcome == "pending")
        prs = sum(len(r.pull_request_urls) for r in records)

        resolution_times: list[float] = []
        for r in records:
            if r.outcome in ("success", "failure") and r.created_at and r.updated_at:
                try:
                    delta = float(r.updated_at) - float(r.created_at)
                    if delta > 0:
                        resolution_times.append(delta)
                except (ValueError, TypeError):
                    pass

        avg_time = (
            sum(resolution_times) / len(resolution_times) if resolution_times else 0.0
        )
        rate = (successful / completed * 100) if completed > 0 else 0.0

        return Analytics(
            total_sessions=total,
            active_sessions=active,
            completed_sessions=completed,
            successful_sessions=successful,
            failed_sessions=failed,
            pending_sessions=pending,
            success_rate=rate,
            prs_created=prs,
            avg_resolution_seconds=avg_time,
            records=records,
        )

    def get_record(self, session_id: str) -> Optional[RemediationRecord]:
        """Get a specific remediation record."""
        return self._records.get(session_id)

    @property
    def records(self) -> list[RemediationRecord]:
        return list(self._records.values())
