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
"""Scanners that detect vulnerabilities, outdated deps, and code quality issues."""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path

from .models import IssueCategory, IssueSeverity, ScannedIssue

logger = logging.getLogger(__name__)

SEVERITY_MAP: dict[str, IssueSeverity] = {
    "critical": IssueSeverity.CRITICAL,
    "high": IssueSeverity.HIGH,
    "medium": IssueSeverity.MEDIUM,
    "low": IssueSeverity.LOW,
    "moderate": IssueSeverity.MEDIUM,
}


def _make_id(*parts: str) -> str:
    """Create a deterministic issue ID from key parts."""
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def scan_python_vulnerabilities(repo_path: str) -> list[ScannedIssue]:
    """Run pip-audit against the repo's requirements to find known CVEs."""
    issues: list[ScannedIssue] = []
    requirements_dir = Path(repo_path) / "requirements"

    for req_file in sorted(requirements_dir.glob("*.txt")):
        logger.info("Scanning %s with pip-audit", req_file.name)
        try:
            cmd = [  # noqa: S603, S607
                "pip-audit",
                "--requirement",
                str(req_file),
                "--format",
                "json",
                "--no-deps",
            ]
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path,
            )
            if result.returncode not in (0, 1):
                logger.warning(
                    "pip-audit exited %d for %s: %s",
                    result.returncode,
                    req_file.name,
                    result.stderr[:500],
                )
                continue

            data = json.loads(result.stdout) if result.stdout.strip() else {}
            vulnerabilities = data.get("dependencies", [])
            for dep in vulnerabilities:
                pkg_name = dep.get("name", "")
                pkg_version = dep.get("version", "")
                for vuln in dep.get("vulns", []):
                    vuln_id = vuln.get("id", "")
                    fix_versions = vuln.get("fix_versions", [])
                    fix_ver = fix_versions[0] if fix_versions else ""
                    desc = vuln.get("description", f"Vulnerability {vuln_id}")
                    severity_str = vuln.get("severity", "medium")
                    issues.append(
                        ScannedIssue(
                            issue_id=_make_id("vuln", pkg_name, vuln_id),
                            category=IssueCategory.VULNERABILITY,
                            severity=SEVERITY_MAP.get(
                                severity_str.lower(), IssueSeverity.MEDIUM
                            ),
                            title=f"{vuln_id}: {pkg_name}=={pkg_version}",
                            description=desc[:500],
                            package=pkg_name,
                            current_version=pkg_version,
                            fixed_version=fix_ver,
                            file_path=str(req_file.relative_to(repo_path)),
                            advisory_id=vuln_id,
                        )
                    )
        except subprocess.TimeoutExpired:
            logger.warning("pip-audit timed out for %s", req_file.name)
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "Failed to parse pip-audit output for %s: %s", req_file.name, exc
            )

    logger.info("Found %d Python vulnerability issues", len(issues))
    return issues


def _parse_outdated_dep(
    dep: dict[str, object],
    req_file: Path,
    repo_path: str,
) -> list[ScannedIssue]:
    """Extract upgrade issues from a single dependency entry."""
    results: list[ScannedIssue] = []
    pkg_name = str(dep.get("name", ""))
    pkg_version = str(dep.get("version", ""))
    skip_reason = dep.get("skip_reason")
    if skip_reason and "not installed" in str(skip_reason).lower():
        return results
    vulns: list[dict[str, object]] = dep.get("vulns", [])  # type: ignore[assignment]
    for vuln in vulns:
        fix_versions: list[str] = vuln.get("fix_versions", [])  # type: ignore[assignment]
        if not fix_versions:
            continue
        fix_ver = fix_versions[0]
        results.append(
            ScannedIssue(
                issue_id=_make_id("upgrade", pkg_name, pkg_version, fix_ver),
                category=IssueCategory.DEPENDENCY_UPGRADE,
                severity=IssueSeverity.MEDIUM,
                title=(f"Upgrade {pkg_name} {pkg_version} -> {fix_ver}"),
                description=(
                    f"Package {pkg_name} has a newer"
                    f" version {fix_ver} that fixes"
                    " known issues."
                ),
                package=pkg_name,
                current_version=pkg_version,
                fixed_version=fix_ver,
                file_path=str(req_file.relative_to(repo_path)),
            )
        )
    return results


def scan_outdated_python_deps(
    repo_path: str,
) -> list[ScannedIssue]:
    """Identify outdated Python packages via pip-audit."""
    issues: list[ScannedIssue] = []
    requirements_dir = Path(repo_path) / "requirements"

    for req_file in sorted(requirements_dir.glob("*.txt")):
        logger.info("Checking outdated deps in %s", req_file.name)
        try:
            cmd = [  # noqa: S603, S607
                "pip-audit",
                "--requirement",
                str(req_file),
                "--format",
                "json",
                "--no-deps",
            ]
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path,
            )
            if not result.stdout.strip():
                continue

            data = json.loads(result.stdout)
            for dep in data.get("dependencies", []):
                issues.extend(_parse_outdated_dep(dep, req_file, repo_path))
        except subprocess.TimeoutExpired:
            logger.warning(
                "Outdated-dep scan timed out for %s",
                req_file.name,
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "Failed to parse outdated deps for %s: %s",
                req_file.name,
                exc,
            )

    # Deduplicate by issue_id
    seen: set[str] = set()
    unique: list[ScannedIssue] = []
    for issue in issues:
        if issue.issue_id not in seen:
            seen.add(issue.issue_id)
            unique.append(issue)

    logger.info("Found %d outdated-dep issues", len(unique))
    return unique


def scan_code_quality(repo_path: str) -> list[ScannedIssue]:
    """Run ruff to detect code quality issues in the Python backend."""
    issues: list[ScannedIssue] = []
    superset_dir = Path(repo_path) / "superset"

    if not superset_dir.is_dir():
        logger.warning("superset/ directory not found at %s", repo_path)
        return issues

    logger.info("Running ruff on superset/ directory")
    try:
        cmd = [  # noqa: S603, S607
            "ruff",
            "check",
            str(superset_dir),
            "--output-format",
            "json",
            "--select",
            "S,B,C90,UP",
            "--no-fix",
        ]
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_path,
        )
        if not result.stdout.strip():
            logger.info("ruff found no issues")
            return issues

        findings = json.loads(result.stdout)

        severity_for_code: dict[str, IssueSeverity] = {}
        for prefix, sev in [
            ("S", IssueSeverity.HIGH),
            ("B", IssueSeverity.MEDIUM),
            ("C90", IssueSeverity.LOW),
            ("UP", IssueSeverity.LOW),
        ]:
            severity_for_code[prefix] = sev

        for finding in findings[:50]:
            code: str = finding.get("code", "")
            message: str = finding.get("message", "")
            filename: str = finding.get("filename", "")
            row: int = finding.get("location", {}).get("row", 0)

            rel_path = filename
            try:
                rel_path = str(Path(filename).relative_to(repo_path))
            except ValueError:
                pass

            sev = IssueSeverity.MEDIUM
            for prefix, mapped_sev in severity_for_code.items():
                if code.startswith(prefix):
                    sev = mapped_sev
                    break

            issues.append(
                ScannedIssue(
                    issue_id=_make_id("quality", code, filename, str(row)),
                    category=IssueCategory.CODE_QUALITY,
                    severity=sev,
                    title=f"{code}: {message}",
                    description=f"{code} at {rel_path}:{row} - {message}",
                    file_path=rel_path,
                )
            )
    except subprocess.TimeoutExpired:
        logger.warning("ruff timed out")
    except (json.JSONDecodeError, KeyError) as exc:
        logger.warning("Failed to parse ruff output: %s", exc)

    logger.info("Found %d code quality issues", len(issues))
    return issues


def run_all_scans(repo_path: str) -> list[ScannedIssue]:
    """Execute all scanners and return a combined, deduplicated issue list."""
    all_issues: list[ScannedIssue] = []

    all_issues.extend(scan_python_vulnerabilities(repo_path))
    all_issues.extend(scan_outdated_python_deps(repo_path))
    all_issues.extend(scan_code_quality(repo_path))

    seen: set[str] = set()
    unique: list[ScannedIssue] = []
    for issue in all_issues:
        if issue.issue_id not in seen:
            seen.add(issue.issue_id)
            unique.append(issue)

    unique.sort(
        key=lambda i: (
            list(IssueSeverity).index(i.severity),
            i.category.value,
        )
    )

    logger.info("Total unique issues across all scans: %d", len(unique))
    return unique
