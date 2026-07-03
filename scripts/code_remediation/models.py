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
"""Data models for the code remediation system."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class IssueSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IssueCategory(Enum):
    VULNERABILITY = "vulnerability"
    DEPENDENCY_UPGRADE = "dependency_upgrade"
    CODE_QUALITY = "code_quality"


class SessionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass
class ScannedIssue:
    """A single issue discovered by scanning."""

    issue_id: str
    category: IssueCategory
    severity: IssueSeverity
    title: str
    description: str
    package: str = ""
    current_version: str = ""
    fixed_version: str = ""
    file_path: str = ""
    advisory_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "package": self.package,
            "current_version": self.current_version,
            "fixed_version": self.fixed_version,
            "file_path": self.file_path,
            "advisory_id": self.advisory_id,
        }


@dataclass
class RemediationTask:
    """Tracks a remediation attempt for one or more issues."""

    task_id: str
    issues: list[ScannedIssue]
    devin_session_id: str = ""
    devin_session_url: str = ""
    status: SessionStatus = SessionStatus.PENDING
    pr_url: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str = ""
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "issues": [i.to_dict() for i in self.issues],
            "devin_session_id": self.devin_session_id,
            "devin_session_url": self.devin_session_url,
            "status": self.status.value,
            "pr_url": self.pr_url,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "error_message": self.error_message,
        }


@dataclass
class RunReport:
    """Aggregated analytics for a single automation run."""

    run_id: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str = ""
    total_issues_found: int = 0
    issues_by_category: dict[str, int] = field(default_factory=dict)
    issues_by_severity: dict[str, int] = field(default_factory=dict)
    tasks_created: int = 0
    tasks_succeeded: int = 0
    tasks_failed: int = 0
    tasks_timed_out: int = 0
    prs_created: list[str] = field(default_factory=list)
    tasks: list[RemediationTask] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_issues_found": self.total_issues_found,
            "issues_by_category": self.issues_by_category,
            "issues_by_severity": self.issues_by_severity,
            "tasks_created": self.tasks_created,
            "tasks_succeeded": self.tasks_succeeded,
            "tasks_failed": self.tasks_failed,
            "tasks_timed_out": self.tasks_timed_out,
            "prs_created": self.prs_created,
            "tasks": [t.to_dict() for t in self.tasks],
        }
