# Devin Issue Remediation Automation

Automated bug fixing pipeline that uses the [Devin API](https://docs.devin.ai/api-reference/overview)
to remediate GitHub issues. When an issue is created or labeled with `devin-fix`, a Devin session
is automatically spawned to analyze, fix, and submit a pull request.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│ GitHub Issue  │────▶│ Devin Automation │────▶│ Devin Session│
│ (devin-fix)  │     │ (event trigger)  │     │ (fix + PR)   │
└──────────────┘     └──────────────────┘     └──────┬───────┘
                                                     │
                     ┌──────────────────┐            │
                     │ Analytics        │◀───────────┘
                     │ Dashboard        │
                     │ (FastAPI + API)  │
                     └──────────────────┘
```

### Components

| Component | File | Purpose |
|-----------|------|---------|
| **Devin API Client** | `devin_client.py` | Typed wrapper for Devin REST API v3 |
| **Session Monitor** | `monitor.py` | Tracks sessions, computes analytics, persists state |
| **Dashboard** | `dashboard.py` | FastAPI app with live HTML dashboard + JSON API |
| **Report Generator** | `report.py` | CLI tool for text/JSON/HTML reports |

### Trigger Mechanism

Two trigger paths are supported:

1. **Devin Automation (recommended)**: A built-in Devin Automation listens for
   `github:issues` events on the target repo. When an issue is opened or labeled
   with `devin-fix`, Devin starts a session with a prompt constructed from the issue.

2. **Webhook (standalone)**: The dashboard exposes a `POST /webhook` endpoint that
   receives GitHub webhook payloads and creates Devin sessions via the API.

## Setup

### Prerequisites

- Python 3.10+
- A Devin API key and org ID ([docs](https://docs.devin.ai/api-reference/teams-quick-start))

### Installation

```bash
cd automation
pip install -r requirements.txt
```

### Environment Variables

```bash
export DEVIN_API_KEY="cog_..."          # Devin service user API key
export DEVIN_ORG_ID="org-..."           # Devin organization ID
export TARGET_REPO="yairk8/superset"    # GitHub repo to monitor
export REMEDIATION_LABEL="devin-fix"    # Label that triggers remediation
export GITHUB_WEBHOOK_SECRET=""         # Optional: webhook HMAC secret
```

### Running the Dashboard

```bash
python dashboard.py
# Dashboard at http://localhost:8765
# API at http://localhost:8765/api/analytics
```

### Generating Reports

```bash
# Text summary
python report.py

# JSON output
python report.py --json

# HTML report
python report.py --output report.html

# Refresh session statuses first
python report.py --refresh
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Live HTML analytics dashboard |
| `GET` | `/api/analytics` | Aggregated metrics (JSON) |
| `GET` | `/api/sessions` | All tracked sessions (JSON) |
| `POST` | `/api/refresh` | Trigger manual status refresh |
| `POST` | `/webhook` | GitHub issue webhook receiver |

## Analytics & Reporting

The dashboard answers key questions for engineering leaders:

- **Is it working?** — Success rate and system status indicator (Healthy/Needs Attention/Critical)
- **What's active?** — Count of sessions in progress with live status
- **What happened?** — Per-issue outcome tracking with links to PRs and Devin sessions
- **How fast?** — Average resolution time from issue creation to PR
- **How much?** — Total throughput: sessions created, PRs opened

## Creating Test Issues

To trigger the automation, create a GitHub issue with the `devin-fix` label:

```bash
gh issue create \
  --repo yairk8/superset \
  --title "Fix: add missing type hints in utils/date_parser.py" \
  --body "The date_parser.py utility is missing type annotations..." \
  --label devin-fix
```
