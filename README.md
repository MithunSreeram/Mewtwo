# Mewtwo

Mewtwo is a personal AI-assisted toolkit that acts as my sidekick throughout the entire bug bounty workflow — from recon to report. It bridges a purple team offensive mindset with BB-specific methodology: thinks like an attacker to surface the attack surface, documents like a defender to produce clean, professional reports.

---

## Requirements

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/) (for AI features)
- Optional tools for active recon: `subfinder`, `nmap`

---

## Installation

```bash
git clone https://github.com/MithunSreeram/Mewtwo.git
cd Mewtwo
pip install -e .
```

Copy the environment template and add your API key:

```bash
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-...
```

Verify the install:

```bash
mewtwo --version
```

---

## Workflow

```
mewtwo init <target>      →  Create workspace
mewtwo scope add          →  Define in-scope domains
mewtwo recon run          →  Enumerate attack surface
mewtwo surface map        →  Map attack vectors
mewtwo hunt run           →  Hunt for vulnerabilities
mewtwo findings list      →  Review findings
mewtwo report generate    →  Generate report
```

---

## Step-by-Step Usage

### 1. Create a Workspace

```bash
mewtwo init "HackerOne Example" --platform hackerone --program-url https://hackerone.com/example --domain example.com
```

This creates `~/.mewtwo/workspaces/hackerone-example/` with a local SQLite database and sets it as the active workspace.

Switch between workspaces at any time:

```bash
mewtwo use hackerone-example
mewtwo list          # see all workspaces
mewtwo status        # summary of current workspace progress
```

---

### 2. Define Scope

```bash
# Add in-scope patterns
mewtwo scope add '*.example.com' --type in
mewtwo scope add 'api.example.com' --type in

# Mark out-of-scope
mewtwo scope add 'staging.example.com' --type out

# List scope
mewtwo scope list
```

---

### 3. Recon

Run passive + active subdomain enumeration, probe alive hosts, fingerprint technologies, crawl URLs, and extract JS secrets:

```bash
# Full recon pipeline
mewtwo recon run -d example.com

# Passive only (no active probing)
mewtwo recon run -d example.com --passive-only

# Individual steps
mewtwo recon subdomains -d example.com
mewtwo recon crawl -u https://example.com
mewtwo recon tech -u https://example.com
mewtwo recon ports -d example.com
```

View results:

```bash
mewtwo recon subdomains --list
mewtwo recon urls --list
```

---

### 4. Attack Surface Mapping

Map recon data into categorised attack vectors (authentication, injection, SSRF, IDOR, etc.):

```bash
mewtwo surface map

# AI-assisted expansion — Claude analyses recon and suggests additional vectors
mewtwo surface map --ai

# List all mapped vectors
mewtwo surface list

# Filter by category
mewtwo surface list --category injection
```

---

### 5. Hunt

Run automated vulnerability checks against all unmapped attack vectors:

```bash
mewtwo hunt run

# Limit to specific vulnerability class
mewtwo hunt run --check xss
mewtwo hunt run --check sqli
mewtwo hunt run --check ssrf
mewtwo hunt run --check idor
mewtwo hunt run --check auth
mewtwo hunt run --check cors
mewtwo hunt run --check open_redirect
mewtwo hunt run --check info_disclosure

# AI triage — Claude reviews and scores each candidate finding
mewtwo hunt run --ai-triage
```

Checks built in:

| Check | What it tests |
|-------|--------------|
| `xss` | Reflected XSS via parameter fuzzing |
| `sqli` | Error-based and time-based SQLi |
| `ssrf` | Server-Side Request Forgery via common params |
| `idor` | Insecure Direct Object Reference patterns |
| `auth` | Missing auth, forced browsing, JWT issues |
| `cors` | Misconfigured CORS headers |
| `open_redirect` | Open redirect via redirect/url params |
| `info_disclosure` | Stack traces, debug pages, exposed secrets |

---

### 6. Manage Findings

```bash
# List all findings
mewtwo findings list

# Filter by severity
mewtwo findings list --severity critical
mewtwo findings list --severity high

# View a specific finding
mewtwo findings show <id>

# Add a finding manually
mewtwo findings add

# Edit finding details
mewtwo findings edit <id>

# Update status
mewtwo findings status <id> confirmed
mewtwo findings status <id> reported

# Calculate CVSS score interactively
mewtwo findings cvss <id>

# AI enrichment — Claude writes impact, reproduction steps, and remediation
mewtwo findings enrich <id>
```

Severity levels: `critical` · `high` · `medium` · `low` · `informational`

Status flow: `draft` → `confirmed` → `reported` → `accepted` / `duplicate` / `informative` / `closed`

---

### 7. Generate Report

```bash
# Markdown report (default)
mewtwo report generate

# HTML report
mewtwo report generate --format html

# Include only confirmed/reported findings
mewtwo report generate --status confirmed --status reported

# AI-generated executive summary
mewtwo report generate --ai

# Specify output path
mewtwo report generate --output ~/reports/example-report.md
```

Reports are saved to `~/.mewtwo/workspaces/<slug>/reports/` by default.

---

### 8. AI Assistant

Ask Claude anything about your current workspace:

```bash
mewtwo ai ask "What are the highest priority vectors I should focus on?"
mewtwo ai ask "Suggest payloads for the login endpoint"
mewtwo ai ask "Summarise all findings found so far"

# Stream the response
mewtwo ai ask "What attack chains could link these findings?" --stream
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for all AI features |
| `MEWTWO_HOME` | Override workspace directory (default: `~/.mewtwo`) |

---

## Directory Structure

```
~/.mewtwo/
├── current -> workspaces/example-com/   # symlink to active workspace
└── workspaces/
    └── example-com/
        ├── mewtwo.db      # SQLite database
        ├── reports/       # Generated reports
        └── evidence/      # Screenshots, request/response dumps
```

---

## Project Layout

```
mewtwo/
├── cli.py                  # Root CLI + workspace commands
├── config.py               # Workspace paths and active workspace
├── db.py                   # SQLite schema
├── models/                 # Pydantic data models
├── storage/                # Repository pattern (DB access)
├── utils/                  # Console, HTTP, process helpers
└── modules/
    ├── ai/                 # Anthropic SDK client + prompts + tools
    ├── recon/              # Subdomain enum, crawl, tech, ports, JS
    ├── surface/            # Attack surface mapping + heuristics
    ├── hunt/               # Vuln checks + runner
    ├── findings/           # CVSS calculator + findings CLI
    └── report/             # Report builder + Jinja2 templates
```
