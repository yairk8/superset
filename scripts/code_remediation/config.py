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
"""Configuration for the code remediation automation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    """Immutable configuration loaded from environment variables."""

    devin_api_key: str = field(
        default_factory=lambda: os.environ.get("DEVIN_API_KEY", "")
    )
    devin_api_base: str = "https://api.devin.ai/v1"
    repo: str = "yairk8/superset"
    repo_path: str = field(
        default_factory=lambda: os.environ.get(
            "REPO_PATH", os.path.join(os.path.expanduser("~"), "repos", "superset")
        )
    )

    max_concurrent_sessions: int = 3
    max_acu_per_session: int = 5
    poll_interval_seconds: int = 30
    session_timeout_seconds: int = 1800

    report_path: str = field(
        default_factory=lambda: os.environ.get(
            "REPORT_PATH",
            os.path.join(
                os.path.expanduser("~"),
                "repos",
                "superset",
                "scripts",
                "code_remediation",
                "reports",
            ),
        )
    )
    run_tag: str = "code-remediation-auto"

    def validate(self) -> list[str]:
        """Return a list of configuration errors, empty if valid."""
        errors: list[str] = []
        if not self.devin_api_key:
            errors.append("DEVIN_API_KEY environment variable is required")
        if not self.repo:
            errors.append("repo must be set")
        return errors
