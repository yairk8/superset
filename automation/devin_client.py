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
"""Devin API v3 client for session management and monitoring."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "https://api.devin.ai/v3/organizations"


@dataclass
class DevinSession:
    """Represents a Devin session with its metadata."""

    session_id: str
    status: str
    title: str = ""
    status_detail: str = ""
    created_at: str = ""
    updated_at: str = ""
    pull_request_urls: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    url: str = ""


class DevinClient:
    """Client for Devin API v3 operations."""

    def __init__(self, api_key: str, org_id: str) -> None:
        self.api_key = api_key
        self.org_id = org_id
        self.base_url = f"{BASE_URL}/{org_id}"
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    def create_session(
        self,
        prompt: str,
        repos: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        max_acu_limit: Optional[int] = None,
    ) -> DevinSession:
        """Create a new Devin session to remediate an issue."""
        payload: dict[str, object] = {"prompt": prompt}
        if repos:
            payload["repos"] = repos
        if tags:
            payload["tags"] = tags
        if max_acu_limit:
            payload["max_acu_limit"] = max_acu_limit

        resp = self._client.post(f"{self.base_url}/sessions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return DevinSession(
            session_id=data["session_id"],
            status=data.get("status", "created"),
            title=data.get("title", ""),
            url=data.get("url", ""),
        )

    def get_session(self, session_id: str) -> DevinSession:
        """Get the status and details of a Devin session."""
        resp = self._client.get(f"{self.base_url}/sessions/{session_id}")
        resp.raise_for_status()
        data = resp.json()
        return DevinSession(
            session_id=data["session_id"],
            status=data.get("status", "unknown"),
            title=data.get("title", ""),
            status_detail=data.get("status_detail", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            pull_request_urls=data.get("pull_request_urls", []),
            tags=data.get("tags", []),
            url=data.get("url", ""),
        )

    def list_sessions(
        self,
        tags: Optional[list[str]] = None,
        first: int = 50,
        after: Optional[str] = None,
    ) -> tuple[list[DevinSession], Optional[str]]:
        """List sessions, optionally filtered by tags."""
        params: dict[str, object] = {"first": first}
        if tags:
            params["tags"] = tags
        if after:
            params["after"] = after

        resp = self._client.get(f"{self.base_url}/sessions", params=params)
        resp.raise_for_status()
        data = resp.json()

        sessions = []
        for item in data.get("data", []):
            sessions.append(
                DevinSession(
                    session_id=item["session_id"],
                    status=item.get("status", "unknown"),
                    title=item.get("title", ""),
                    status_detail=item.get("status_detail", ""),
                    created_at=item.get("created_at", ""),
                    updated_at=item.get("updated_at", ""),
                    pull_request_urls=item.get("pull_request_urls", []),
                    tags=item.get("tags", []),
                    url=item.get("url", ""),
                )
            )

        next_cursor = data.get("page_info", {}).get("end_cursor")
        return sessions, next_cursor

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
