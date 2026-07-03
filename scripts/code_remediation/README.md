# Automated Code Remediation System

An event-driven automation that scans the Superset codebase for vulnerabilities,
outdated dependencies, and code quality issues, then uses the
[Devin API](https://docs.devin.ai/api-reference/overview) to programmatically
create sessions that fix them and open pull requests.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Trigger    │────▶│   Scanner    │────▶│ Devin Client │────▶│  Reporter    │
│  (schedule)  │     │  pip-audit   │     │  REST API    │     │  MD + JSON   │
│              │     │  ruff        │     │  v1/sessions │     │  analytics   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            │                    │                     │
                            ▼                    ▼                     ▼
                     ScannedIssue[]      RemediationTask[]        RunReport
                                               │
                                               ▼
                                          Pull Requests
```

### Trigger

A **Devin Automation** fires on a recurring schedule (daily at 09:00 UTC by
default). When triggered, Devin runs this script inside a session, which in turn
creates *child* Devin sessions — one per issue batch — to perform the actual
fixes.

### Scanners

| Scanner | Tool | What it detects |
|---------|------|-----------------|
| `scan_python_vulnerabilities` | `pip-audit` | Known CVEs in pinned Python deps |
| `scan_outdated_python_deps` | `pip-audit` | Deps with available security patches |
| `scan_code_quality` | `ruff` | Security (S), bug-risk (B), complexity (C90), modernization (UP) |

### Devin API Integration

For each batch of issues the system calls **`POST /v1/sessions`** with a
self-contained prompt describing the issues and fix instructions. Sessions are
tagged for tracking and capped at a configurable ACU limit.

### Reporting / Analytics

After all sessions complete (or time out), the system produces:

- **Markdown report** — human-readable summary with tables
- **JSON report** — machine-readable for downstream tooling
- **Trend summary** — aggregated stats across historical runs

Key metrics exposed:

| Metric | Description |
|--------|-------------|
| Issues found | Total issues detected by scanners |
| Sessions created | Devin sessions launched |
| Success rate | % of sessions that produced a PR |
| PRs created | Links to opened pull requests |
| Throughput | Issues processed per run |

## Usage

### Prerequisites

```bash
pip install -r scripts/code_remediation/requirements.txt
```

### Scan Only (no Devin sessions)

```bash
python -m scripts.code_remediation --scan-only
```

### Full Run (scan + Devin sessions + report)

```bash
export DEVIN_API_KEY="your-api-key"
python -m scripts.code_remediation
```

### View Trends

```bash
python -m scripts.code_remediation --trends
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEVIN_API_KEY` | *(required)* | Devin API bearer token |
| `REPO_PATH` | `~/repos/superset` | Local path to the repo |
| `REPORT_PATH` | `scripts/code_remediation/reports/` | Where to write reports |

## How an Engineering Leader Knows This Is Working

1. **Reports** land in `scripts/code_remediation/reports/` after every run —
   check the latest `report_*.md` for a summary table.
2. **PRs tagged `automated-remediation`** appear in the GitHub repo.
3. **Trend summary** (`--trends`) shows success rates and throughput over time.
4. **Devin sessions** are tagged `code-remediation-auto` and visible in the
   Devin dashboard at <https://app.devin.ai>.
5. **JSON reports** can be ingested by monitoring/alerting tools (Datadog,
   Grafana, etc.) for dashboards.
